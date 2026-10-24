#!/usr/bin/env python3
"""Deterministic, evidence-first deletion audit engine."""
from __future__ import annotations
import argparse, csv, json, re, sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

OUTPUT_FIELDS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
ALLOWED = {
("FINDING","REPORT_REMAINING_RECORD","PRESENT"),("FINDING","REPORT_EXPOSED_PII","PRESENT"),
("FINDING","REPORT_ACTIVE_DATA_FLOW","ACTIVE"),("FINDING","REPORT_RESTORE_RISK","ACTIVE"),
("REMEDIATION","DISABLE_DATA_FLOW","DISABLED"),("REMEDIATION","BLOCK_RESTORE","BLOCKED"),
("REMEDIATION","DELETE_RECORD","ABSENT"),("REMEDIATION","REDACT_RECORD","REDACTED"),
("REMEDIATION","ANONYMIZE_RECORD","ANONYMIZED"),("VERIFICATION","VERIFY_RECORD_ABSENT","ABSENT"),
("VERIFICATION","VERIFY_RECORD_PRESENT","PRESENT"),("VERIFICATION","VERIFY_RECORD_REDACTED","REDACTED"),
("VERIFICATION","VERIFY_RECORD_ANONYMIZED","ANONYMIZED"),("VERIFICATION","VERIFY_DATA_FLOW_DISABLED","DISABLED"),
("VERIFICATION","VERIFY_RESTORE_BLOCKED","BLOCKED")}
OP_ORDER={"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,
"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,
"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,
"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5}
NEGATION_RE=re.compile(r"\b(?:do not|don't|dont|never|not|without)\b.{0,45}\b(?:delete|deletion|erase|erasure|remove|removal|close|closure|account)\b",re.I)
NON_DELETE_RE=re.compile(r"\b(?:access|export|download|correct|correction|update|rectify|marketing opt[- ]?out|unsubscribe|stop marketing|change my email)\b",re.I)
DELETE_RE=re.compile(r"\b(?:delet(?:e|ion|ing)|eras(?:e|ure|ing)|remov(?:e|al|ing)|close(?:d|ing)?\s+(?:my\s+)?account|permanent(?:ly)?\s+(?:account\s+)?deletion|wipe)\b",re.I)

class InputError(ValueError): pass

def read_csv(path: Path, required: Iterable[str]) -> list[dict[str,str]]:
    if not path.is_file(): raise InputError(f"Required input file is missing: {path}")
    with path.open("r",encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        if reader.fieldnames is None: raise InputError(f"CSV has no header: {path}")
        missing=sorted(set(required)-set(reader.fieldnames))
        if missing: raise InputError(f"{path}: missing required columns: {', '.join(missing)}")
        rows=list(reader)
    if not rows: raise InputError(f"CSV contains no data rows: {path}")
    return rows

def parse_time(value: str) -> datetime:
    try: out=datetime.fromisoformat(value.replace("Z","+00:00"))
    except (TypeError,ValueError) as e: raise InputError(f"Invalid ISO-8601 timestamp: {value!r}") from e
    return (out if out.tzinfo else out.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)

def normalize(value: str|None)->str: return (value or "").strip().casefold()

def request_authorizes_deletion(text: str)->bool:
    s=text.strip()
    if not s or NEGATION_RE.search(s): return False
    if NON_DELETE_RE.search(s) and not DELETE_RE.search(s): return False
    if re.search(r"(?i)\b(?:supprim|elimin|exclus|exclusão|elimina|borrar|eliminar|cancelar|삭제|消除|削除|删除)\w*",s): return True
    return bool(DELETE_RE.search(s))

def load_inputs(dataset: Path, requests_file: Path | None = None)->dict[str,Any]:
    requests=read_csv(requests_file or (dataset/"deletion_requests.csv"),["case_id","email","requested_at","reported_status","reported_at","audit_at","request_text"])
    identities=read_csv(dataset/"user_identities.csv",["user_id","name","email","phone","email_hash","updated_at"])
    audit=read_csv(dataset/"user_audit_log.csv",["audit_id","user_id","event_time","field_name","old_value","new_value"])
    activity=read_csv(dataset/"system_activity.csv",["activity_id","event_time","event_type","source_system","target_system","resource_id","reported_result","details"])
    rules=read_csv(dataset/"deletion_rules.csv",["rule_id","data_category","condition","required_action"])
    manifest=read_csv(dataset/"evidence_files.csv",["file_id","file_path","origin","captured_at"])
    ids=set()
    for r in requests:
        if not r["case_id"].strip() or r["case_id"] in ids: raise InputError(f"Empty or duplicate case_id: {r['case_id']!r}")
        ids.add(r["case_id"]); parse_time(r["requested_at"]); parse_time(r["audit_at"])
    return {"requests":requests,"identities":identities,"audit":audit,"activity":activity,"rules":rules,"manifest":manifest}

@dataclass(frozen=True)
class EvidenceHit:
    file_id:str
    path:str
    captured_at:datetime
    text:str
@dataclass
class Resource:
    system_id:str
    resource_id:str
    operation:str
    state:str
    evidence_id:str

def read_evidence(dataset:Path,manifest:list[dict[str,str]],cutoff:datetime|None=None)->list[EvidenceHit]:
    hits=[]
    for e in manifest:
        captured=parse_time(e["captured_at"])
        if cutoff is not None and captured>cutoff: continue
        rel=e["file_path"].replace("\\","/").lstrip("/")
        path=(dataset/rel).resolve()
        if not path.is_relative_to(dataset.resolve()) or not path.is_file(): continue
        if path.suffix.lower() not in {".txt",".log",".json",".sql",".csv",".md"}: continue
        try: content=path.read_text(encoding="utf-8",errors="replace")
        except OSError: continue
        hits.append(EvidenceHit(e["file_id"],rel,captured,content))
    return hits

def identity_aliases(email:str,identities:list[dict[str,str]],audit:list[dict[str,str]],cutoff:datetime):
    target=normalize(email); users=set(); aliases={target} if target else set()
    for r in identities:
        if normalize(r["email"])==target and parse_time(r["updated_at"])<=cutoff: users.add(r["user_id"])
    for r in audit:
        if parse_time(r["event_time"])<=cutoff and r["field_name"].casefold()=="email" and normalize(r["old_value"])==target: users.add(r["user_id"])
    changed=True
    while changed:
        changed=False
        for r in audit:
            if parse_time(r["event_time"])>cutoff or r["user_id"] not in users or r["field_name"].casefold()!="email": continue
            for v in (normalize(r["old_value"]),normalize(r["new_value"])):
                if v and v not in aliases: aliases.add(v); changed=True
    return users,aliases

def subject_tokens(users:set[str],aliases:set[str],identities:list[dict[str,str]],audit:list[dict[str,str]],cutoff:datetime)->set[str]:
    tokens=set(aliases)
    for r in identities:
        if r["user_id"] in users:
            tokens.update(normalize(r[k]) for k in ("name","phone","email_hash") if normalize(r[k]))
            tokens.add(normalize(r["user_id"]))
    for r in audit:
        if r["user_id"] in users and parse_time(r["event_time"])<=cutoff:
            tokens.update(normalize(r[k]) for k in ("old_value","new_value") if normalize(r[k]))
    return {t for t in tokens if t}

def _extract_nested_objects(value: Any):
    """Yield each nested mapping; wrappers and embedded JSON need equal treatment."""
    yield from _walk_records(value)

def _record_matches(record: dict[str, Any], aliases: set[str], users: set[str]) -> bool:
    user_keys = {"user_id", "subject_reference", "customer_reference", "customer_id", "account_user_id", "owner_user_id"}
    email_keys = {"email", "display_email", "old_email", "new_email", "customer_email"}
    for key, value in record.items():
        k = str(key).casefold()
        v = _norm_id(value)
        if not v:
            continue
        if k in email_keys and v in aliases:
            return True
        if k in user_keys and v in {_norm_id(u) for u in users}:
            return True
    return False

def json_objects(text:str)->list[dict[str,Any]]:
    try: root=json.loads(text)
    except json.JSONDecodeError: return []
    out=[]
    def walk(x):
        if isinstance(x,dict):
            out.append(x)
            for v in x.values(): walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(root); return out

def infer_system(path:str,rid:str)->str:
    p=(path+" "+rid).casefold()
    for term,sysid in (("search","search_service"),("analytics","analytics_platform"),("telemetry","analytics_platform"),
    ("support","support_platform"),("export","export_service"),("backup","backup_service"),("restore","backup_service"),
    ("flow","integration_service"),("connector","integration_service"),("tombstone","identity_service"),("identity","identity_service"),
    ("audit","security_service"),("security","security_service"),("marketing","marketing_service"),("cache","cache_service"),("account","account_service")):
        if term in p: return sysid
    return "account_service"

def _norm_id(value: Any) -> str:
    return normalize(str(value)) if value is not None else ""

def _contains_subject(record: dict[str, Any], aliases: set[str], tokens: set[str], users: set[str]) -> bool:
    # Match only explicit identifier fields, never arbitrary substrings in a JSON dump.
    for key in ("email", "display_email", "old_email", "new_email"):
        value = _norm_id(record.get(key))
        if value and value in aliases:
            return True
    for key in ("subject_reference", "user_id", "customer_id", "account_user_id"):
        value = _norm_id(record.get(key))
        if value and value in {_norm_id(u) for u in users}:
            return True
    # Hashes and names are weaker identifiers; require exact field/value equality.
    for key in ("email_hash", "phone", "name", "display_name", "old_email", "new_email"):
        value = _norm_id(record.get(key))
        if value and value in tokens:
            return True
    return False

def _walk_records(value: Any, inherited_store: str = "", inherited_collection: str = ""):
    if isinstance(value, dict):
        store = str(value.get("data_store") or inherited_store)
        collection = str(value.get("collection") or inherited_collection)
        # Evidence snapshots commonly nest customer records in multiple service
        # exports and search "documents" arrays. Preserve the service store/collection.
        for key, child in value.items():
            if isinstance(child, str) and key.casefold() in {"record_json", "payload", "document"}:
                try:
                    parsed = json.loads(child)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    yield from _walk_records(parsed, store, collection)
        if any(k in value for k in ("resource_id", "record_id", "id")):
            yield value, store, collection
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from _walk_records(child, store, collection)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_records(child, inherited_store, inherited_collection)

def _resource_category(path: str, store: str, collection: str, rid: str) -> str:
    text = " ".join((path, store, collection, rid)).casefold()
    if "tombstone" in text or "deleted_customer_reference" in text:
        return "tombstone"
    if "security" in text or "audit_record" in text or rid.casefold().startswith("audit_record_"):
        return "retained"
    if "legal" in text or "legal_hold" in text:
        return "retained"
    if "analytics" in text or "telemetry" in text:
        return "analytics"
    if "support" in text or "attachment" in text or "conversation" in text or "ticket" in text:
        return "support"
    if "search" in text or rid.casefold().startswith("search_"):
        return "search"
    if "cache" in text:
        return "cache"
    if "backup" in text or "restore" in text or "archive" in text or "failover" in text:
        return "backup"
    if "flow" in text or "connector" in text or "sync" in text or "integration" in text:
        return "flow"
    if "export" in text or "object_store" in text:
        return "export"
    if "marketing" in text:
        return "marketing"
    return "profile"

def classify_resources(hits:list[EvidenceHit],users:set[str],aliases:set[str],tokens:set[str])->list[Resource]:
    found: dict[tuple[str, str, str], Resource] = {}
    user_norm = {_norm_id(u) for u in users}
    for hit in hits:
        path = hit.path.casefold()
        structured = False
        # Evidence JSON and SQL snapshots are parsed conservatively. A whole-file JSON
        # parse avoids interpreting comments/quoted SQL as actual state.
        if path.endswith(".json"):
            try:
                root = json.loads(hit.text)
            except json.JSONDecodeError:
                root = None
            if root is not None:
                for rec, store, collection in _walk_records(root):
                    if not (_contains_subject(rec, aliases, tokens, users) or _record_matches(rec, aliases, users)):
                        continue
                    rid = str(rec.get("resource_id") or rec.get("record_id") or rec.get("id") or "")
                    if not rid:
                        continue
                    category = _resource_category(path, store, collection, rid)
                    fields = {str(k).casefold(): v for k, v in rec.items()}
                    direct = any(_norm_id(fields.get(k)) for k in ("name", "email", "phone", "email_hash", "display_name", "full_name"))
                    # Search exports often wrap the hit in a query object and repeat
                    # the resource ID on the parent. A nested document's exact subject
                    # match must classify the parent resource, not only the child.
                    if category == "retained":
                        # Policy-retained audit/security records are not residual deletion failures.
                        continue
                    if category == "tombstone":
                        if direct:
                            op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", "identity_service"
                        else:
                            continue
                    elif category == "flow":
                        enabled = str(fields.get("enabled", fields.get("status", ""))).casefold()
                        if enabled in {"true", "1", "enabled", "active", "running"}:
                            op, state, sysid = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", str(rec.get("system_id") or store or "integration_service")
                        else:
                            continue
                    elif category == "backup":
                        restorable = str(fields.get("restorable", fields.get("restore_allowed", fields.get("status", "")))).casefold()
                        if restorable in {"true", "1", "yes", "restorable", "enabled", "active"}:
                            op, state, sysid = "REPORT_RESTORE_RISK", "ACTIVE", str(rec.get("system_id") or store or "backup_service")
                        else:
                            continue
                    elif category == "analytics":
                        op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", str(rec.get("data_store") or store or "analytics_platform")
                    elif category == "support":
                        op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", str(rec.get("data_store") or store or "support_platform")
                    else:
                        op, state, sysid = "REPORT_REMAINING_RECORD", "PRESENT", str(rec.get("data_store") or store or infer_system(path, rid))
                    key = (sysid, rid, op)
                    found[key] = Resource(sysid, rid, op, state, hit.file_id)
                    structured = True
        elif path.endswith(".sql"):
            # SQL files in this dataset are SQLite text dumps with INSERT rows. To
            # avoid treating schema/comments as state, inspect parsed INSERT tuples.
            # Tokens must occur as exact SQL string literals in a row containing a
            # recognized resource id. The row is associated with the table's store.
            insert_re = re.compile(r"INSERT\s+INTO\s+[`\"]?([A-Za-z_][\w]*)[`\"]?(?:\s*\(([^)]*)\))?\s*VALUES\s*\((.*?)\)\s*;", re.I | re.S)
            for match in insert_re.finditer(hit.text):
                table, columns_text, values_text = match.groups()
                columns = ([c.strip().strip('`"[] ') for c in columns_text.split(",")]
                           if columns_text else [])
                if not columns:
                    # SQLite allows INSERT INTO table VALUES(...) without a column list;
                    # use the table definition preceding this row to recover column names.
                    table_match = re.search(r"CREATE\s+TABLE\s+[`\"]?" + re.escape(table) + r"[`\"]?\s*\((.*?)\)\s*;", hit.text, re.I | re.S)
                    if not table_match:
                        continue
                    columns = re.findall(r"^\s*([A-Za-z_][\w]*)\s+(?:TEXT|INTEGER|REAL|BLOB|NUMERIC)", table_match.group(1), re.I | re.M)
                try:
                    values = next(csv.reader([values_text], skipinitialspace=True, quotechar="'"))
                except Exception:
                    continue
                if len(columns) != len(values):
                    continue
                rec = dict(zip((c.casefold() for c in columns), (v.strip().strip("'\\\"") for v in values)))
                if not _contains_subject(rec, aliases, tokens, users):
                    continue
                rid = str(rec.get("resource_id") or rec.get("record_id") or rec.get("id") or "")
                if not rid:
                    continue
                category = _resource_category(path, table, table, rid)
                if category == "retained":
                    continue
                if category == "tombstone":
                    direct = any(_norm_id(rec.get(k)) for k in ("name", "email", "phone", "email_hash", "display_name"))
                    if not direct:
                        continue
                    op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", "identity_service"
                elif category == "analytics":
                    op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", "analytics_platform"
                else:
                    op, state, sysid = "REPORT_REMAINING_RECORD", "PRESENT", infer_system(path, rid)
                found[(sysid, rid, op)] = Resource(sysid, rid, op, state, hit.file_id)
                structured = True
        if structured:
            continue
        # Text evidence: parse each row/line and attach only the evidence identifier
        # that was captured by the manifest before the case's audit cutoff.
        for line in hit.text.splitlines():
            low = line.casefold()
            if not any(alias and alias in low for alias in aliases):
                continue
            ids = re.findall(r"\b(?:account|search|analytics|support|export|backup|tombstone|data_flow|cache|marketing|delivery|telemetry|profile)_?\d+\b", line, re.I)
            for rid in ids:
                category = _resource_category(path, "", "", rid)
                sysid = infer_system(path, rid)
                if category == "retained":
                    continue
                if category == "tombstone" and any(word in low for word in ("name=", "email=", "phone=", "email_hash=")):
                    op, state = "REPORT_EXPOSED_PII", "PRESENT"
                elif category == "flow" and any(word in low for word in ("enabled", "active", "running")):
                    op, state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                elif category == "backup" and any(word in low for word in ("restorable", "restore allowed", "can be restored")):
                    op, state = "REPORT_RESTORE_RISK", "ACTIVE"
                elif category == "analytics" and any(word in low for word in ("identifiable", "email", "attributable", "user_id")):
                    op, state = "REPORT_EXPOSED_PII", "PRESENT"
                else:
                    op, state = "REPORT_REMAINING_RECORD", "PRESENT"
                found[(sysid, rid, op)] = Resource(sysid, rid, op, state, hit.file_id)
    return list(found.values())

def make_step(n:int,phase:str,system:str,rid:str,op:str,state:str,evidence:str)->dict[str,Any]:
    s={"step_no":n,"phase":phase,"system_id":system,"resource_id":rid,"operation":op,"state":state,"evidence_id":evidence}
    if list(s)!=STEP_FIELDS or (phase,op,state) not in ALLOWED: raise InputError(f"Invalid step: {s}")
    if phase=="FINDING" and not evidence: raise InputError("Finding must cite evidence")
    return s

def build_plan(resources:list[Resource])->list[dict[str,Any]]:
    unique=[]; seen=set()
    for r in sorted(resources,key=lambda x:(OP_ORDER.get(x.operation,99),x.system_id,x.resource_id)):
        k=(r.system_id,r.resource_id,r.operation)
        if k not in seen: seen.add(k); unique.append(r)
    steps=[]
    for r in unique: steps.append(make_step(len(steps)+1,"FINDING",r.system_id,r.resource_id,r.operation,r.state,r.evidence_id))
    rem=[]; ver=[]
    for r in unique:
        if r.operation=="REPORT_REMAINING_RECORD": rop,rstate,vop,vstate="DELETE_RECORD","ABSENT","VERIFY_RECORD_ABSENT","ABSENT"
        elif r.operation=="REPORT_EXPOSED_PII":
            if "analytics" in r.system_id: rop,rstate,vop,vstate="ANONYMIZE_RECORD","ANONYMIZED","VERIFY_RECORD_ANONYMIZED","ANONYMIZED"
            else: rop,rstate,vop,vstate="REDACT_RECORD","REDACTED","VERIFY_RECORD_REDACTED","REDACTED"
        elif r.operation=="REPORT_ACTIVE_DATA_FLOW": rop,rstate,vop,vstate="DISABLE_DATA_FLOW","DISABLED","VERIFY_DATA_FLOW_DISABLED","DISABLED"
        elif r.operation=="REPORT_RESTORE_RISK": rop,rstate,vop,vstate="BLOCK_RESTORE","BLOCKED","VERIFY_RESTORE_BLOCKED","BLOCKED"
        else: continue
        rem.append((OP_ORDER[rop],r.system_id,r.resource_id,rop,rstate))
        ver.append((OP_ORDER[vop],r.system_id,r.resource_id,vop,vstate))
    for _,sysid,rid,op,state in sorted(rem): steps.append(make_step(len(steps)+1,"REMEDIATION",sysid,rid,op,state,""))
    for _,sysid,rid,op,state in sorted(ver): steps.append(make_step(len(steps)+1,"VERIFICATION",sysid,rid,op,state,""))
    return steps

def _activity_resources(case: dict[str, str], data: dict[str, Any], users: set[str], aliases: set[str], cutoff: datetime) -> list[Resource]:
    # The activity export is global and its rows do not contain subject IDs in
    # dedicated columns. Therefore it cannot safely be attributed to a subject here.
    # Resource-specific evidence files provide the evidence-linked findings.
    return []

def audit_case(case:dict[str,str],data:dict[str,Any],dataset:Path,evidence_cache:list[EvidenceHit])->tuple[str,list[dict[str,Any]]]:
    cutoff = parse_time(case["audit_at"])
    if not request_authorizes_deletion(case["request_text"]):
        return "NOT_APPLICABLE", []

    users, aliases = identity_aliases(case["email"], data["identities"], data["audit"], cutoff)
    if not users:
        # Do not invent identifiers or treat an unresolvable identity as proof of absence.
        return "INCOMPLETE", []

    tokens = subject_tokens(users, aliases, data["identities"], data["audit"], cutoff)
    hits = [h for h in evidence_cache if h.captured_at <= cutoff]
    resources = classify_resources(hits, users, aliases, tokens)
    resources.extend(_activity_resources(case, data, users, aliases, cutoff))
    plan = build_plan(resources)

    # A clean result requires explicit negative-state evidence for the account and
    # any policy-relevant retained resources. The positive-evidence scanner does not
    # have enough information to assert COMPLETE by itself.
    return "INCOMPLETE", plan

def validate_output(rows:list[dict[str,str]],expected:set[str])->None:
    if not rows or list(rows[0])!=OUTPUT_FIELDS: raise InputError("Output header mismatch")
    ids=[r["case_id"] for r in rows]
    if len(ids)!=len(expected) or set(ids)!=expected: raise InputError("Output case coverage mismatch")
    if ids!=sorted(ids): raise InputError("Output rows must be sorted by case_id")
    for row in rows:
        if row["deletion_status"] not in STATUSES: raise InputError(f"Invalid status {row['deletion_status']}")
        try: steps=json.loads(row["steps_json"])
        except json.JSONDecodeError as e: raise InputError(f"Invalid JSON for {row['case_id']}") from e
        if not isinstance(steps,list): raise InputError("steps_json must be a JSON array")
        if row["deletion_status"]=="NOT_APPLICABLE" and steps: raise InputError("NOT_APPLICABLE must have []")
        if row["deletion_status"]=="COMPLETE" and any(s["phase"]!="VERIFICATION" or not s["evidence_id"] for s in steps): raise InputError("COMPLETE requires evidence-backed verification-only steps")
        for i,s in enumerate(steps,1):
            if list(s)!=STEP_FIELDS or s["step_no"]!=i: raise InputError("Invalid step fields/numbering")
            if (s["phase"],s["operation"],s["state"]) not in ALLOWED: raise InputError("Invalid operation/state")
            if s["phase"]=="FINDING" and not s["evidence_id"]: raise InputError("Finding must cite evidence")

def generate(dataset:Path,output:Path,requests_file:Path|None=None)->dict[str,Any]:
    data=load_inputs(dataset,requests_file); results=[]
    max_cutoff=max(parse_time(r["audit_at"]) for r in data["requests"])
    evidence_cache=read_evidence(dataset,data["manifest"],max_cutoff)
    for case in data["requests"]:
        status,steps=audit_case(case,data,dataset,evidence_cache)
        results.append({"case_id":case["case_id"],"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})
    results.sort(key=lambda r:r["case_id"]); validate_output(results,{r["case_id"] for r in data["requests"]})
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("w",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=OUTPUT_FIELDS,lineterminator="\\n"); writer.writeheader(); writer.writerows(results)
    return {"rows":len(results),"statuses":{s:sum(x["deletion_status"]==s for x in results) for s in sorted(STATUSES)},"output":str(output)}


def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset",type=Path,default=Path("dataset")); p.add_argument("--output",type=Path,default=Path("output.csv"))
    p.add_argument("--validate-only",action="store_true"); p.add_argument("--requests",type=Path,default=None,help="Optional request CSV for sample evaluation"); args=p.parse_args()
    try:
        data=load_inputs(args.dataset,args.requests)
        if args.validate_only: print(json.dumps({"valid":True,"requests":len(data["requests"]),"identities":len(data["identities"]),"audit_rows":len(data["audit"]),"activity_rows":len(data["activity"]),"evidence_manifest_rows":len(data["manifest"])}))
        else: print(json.dumps(generate(args.dataset,args.output,args.requests),ensure_ascii=False))
    except (InputError,OSError) as e: print(f"ghosttrace: error: {e}",file=sys.stderr); return 2
    return 0
if __name__=="__main__": raise SystemExit(main())
