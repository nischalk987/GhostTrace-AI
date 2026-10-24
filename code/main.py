#!/usr/bin/env python3
"""Deterministic, evidence-first deletion audit engine."""
from __future__ import annotations
import argparse, csv, json, re, sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from identity_resolution import IdentityResolver
from temporal_state import TemporalEvent, observation_is_eligible, reconstruct_state, normalize_timestamp

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
NEGATION_RE=re.compile(r"\b(?:do not|don't|dont|never)\s+(?:please\s+)?(?:delete|erase|remove|close|wipe|cancel)\b|\b(?:do not|don't|dont)\s+(?:want|need|wish)\s+(?:you\s+to\s+)?(?:delete|erase|remove|close|wipe)\b",re.I)
NON_DELETE_RE=re.compile(r"\b(?:access|export|download|correct|correction|update|rectify|marketing opt[- ]?out|unsubscribe|stop marketing|change my email)\b",re.I)
DELETE_RE=re.compile(r"\b(?:delet(?:e|ed|es|ing|ion|ions)|eras(?:e|ed|es|ing|ure)|remov(?:e|ed|es|ing|al)|clos(?:e|ed|es|ing)|wip(?:e|ed|ing)|expung(?:e|ed|ing)|eliminat(?:e|ed|ion|ing)|supprim(?:e|er|ée|ission)|effac(?:e|er|ement)|borr(?:a|ar|ado|ada)|exclu(?:ir|são|sion)|apagar|verwijder(?:en|ing)|entfern(?:en|ung)|löschen|loeschen|cancell(?:are|azione|ed)|削除|消去|退会|删除|刪除|注销|注銷|삭제|탈퇴)\b|\bclose\s+(?:(?:my|the|this|an)\s+)?account\b|\b(?:account|profile|personal data|personal information)\b.{0,80}\b(?:gone|deleted|removed|erased|closed|wiped)\b",re.I)

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
    if not s:
        return False
    # Only treat a direct negation of the deletion verb as non-consent. For example,
    # "do not treat a similar search record as mine" is still a deletion audit request.
    if NEGATION_RE.search(s):
        return False
    positive = bool(DELETE_RE.search(s)) or bool(re.search(
        r"(?i)(suppression|supprimer|effacer|elimin|exclus|exclusão|borrar|eliminar|apagar|削除|消去|退会|删除|刪除|注销|注銷|삭제|탈퇴|delete|erase|remove|close|deletion|erasure|account.{0,60}gone|profile.{0,60}gone)",
        s))
    if NON_DELETE_RE.search(s) and not positive:
        return False
    return positive

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

from evidence_index import EvidenceIndex

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
    """Legacy reader for unit callers; production generate() reuses one EvidenceIndex."""
    hits=[]
    root=dataset.resolve()
    for entry in manifest:
        captured=parse_time(entry["captured_at"])
        if cutoff is not None and captured>cutoff:
            continue
        raw=entry["file_path"].replace("\\","/")
        pieces=raw.split("/")
        if any(part==".." for part in pieces):
            continue
        parts=[part for part in pieces if part not in {"",".","dataset"}]
        if not parts or parts[0]!="evidence":
            continue
        path=(root/Path(*parts)).resolve()
        try:
            path.relative_to((root/"evidence").resolve())
        except ValueError:
            continue
        if not path.is_file() or path.suffix.casefold() not in {".txt",".log",".json",".sql",".csv",".md"}:
            continue
        try:
            text=path.read_text(encoding="utf-8-sig")
        except (OSError,UnicodeError):
            continue
        hits.append(EvidenceHit(entry["file_id"],path.relative_to(root).as_posix(),captured,text))
    hits.sort(key=lambda h:(h.captured_at,h.file_id,h.path))
    return hits

def identity_aliases(email:str,identities:list[dict[str,str]],audit:list[dict[str,str]],cutoff:datetime):
    """Resolve one subject conservatively; return no aliases for unknown/conflicted IDs."""
    result=IdentityResolver(identities,audit).resolve_subject(email, audit_at=cutoff, identifier_type="email")
    if result.status != "RESOLVED" or result.user_id is None:
        # Do not let ambiguous historical identifier reuse pull unrelated subjects
        # into an audit. audit_case maps this empty result to INCOMPLETE, never COMPLETE.
        return set(),set()
    user=result.user_id
    target=normalize(email)
    aliases={target} if target else set()
    for r in audit:
        if r["user_id"] != user or r["field_name"].casefold() != "email" or parse_time(r["event_time"])>cutoff:
            continue
        for value in (normalize(r["old_value"]), normalize(r["new_value"])):
            if value:
                aliases.add(value)
    # Include a current snapshot identifier only when it existed by the cutoff.
    for r in identities:
        if r["user_id"] == user and parse_time(r["updated_at"]) <= cutoff:
            value=normalize(r["email"])
            if value:
                aliases.add(value)
    return {user},aliases

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
    email_keys = {"email", "display_email", "old_email", "new_email", "customer_email", "requester_email", "owner_email"}
    normalized_users = {_norm_id(u) for u in users}
    for key, value in record.items():
        k = str(key).casefold()
        v = _norm_id(value)
        if not v:
            continue
        if k in email_keys and v in aliases:
            return True
        if k in user_keys and v in normalized_users:
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
    for key in ("email", "display_email", "old_email", "new_email", "customer_email", "requester_email", "owner_email"):
        value = _norm_id(record.get(key))
        if value and value in aliases:
            return True
    normalized_users = {_norm_id(u) for u in users}
    for key in ("subject_reference", "user_id", "customer_id", "account_user_id", "customer_reference", "owner_user_id"):
        value = _norm_id(record.get(key))
        if value and value in normalized_users:
            return True
    # Hashes and names are weaker identifiers; require exact field/value equality.
    for key in ("email_hash", "phone", "name", "full_name", "display_name", "old_email", "new_email"):
        value = _norm_id(record.get(key))
        if value and value in tokens:
            return True
    return False

def _walk_records(value: Any, inherited_store: str = "", inherited_collection: str = "", inherited_resource_id: str = ""):
    """Yield resource rows, carrying parent IDs to nested payloads.

    Some exports put the email/subject reference in a nested profile/documents
    object while the enclosing lookup contains the only resource_id. The parent
    ID is attached only to child mappings containing identity fields, not metrics.
    """
    if isinstance(value, dict):
        store = str(value.get("data_store") or inherited_store)
        collection = str(value.get("collection") or inherited_collection)
        local_id = str(value.get("resource_id") or value.get("record_id") or value.get("id") or "")
        rid = local_id or inherited_resource_id
        identity_keys = {
            "user_id", "subject_reference", "customer_reference", "customer_id",
            "account_user_id", "owner_user_id", "email", "display_email", "old_email",
            "new_email", "customer_email", "requester_email", "owner_email",
            "email_hash", "phone", "name", "full_name", "display_name",
        }
        has_identity_field = any(str(k).casefold() in identity_keys and v not in (None, "") for k, v in value.items())
        for key, child in value.items():
            if isinstance(child, str) and str(key).casefold() in {"record_json", "payload", "document"}:
                try:
                    parsed = json.loads(child)
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, (dict, list)):
                    yield from _walk_records(parsed, store, collection, rid)
        if local_id or (inherited_resource_id and has_identity_field):
            row = dict(value)
            if not local_id and inherited_resource_id:
                row["resource_id"] = inherited_resource_id
            yield row, store, collection
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from _walk_records(child, store, collection, rid)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_records(child, inherited_store, inherited_collection, inherited_resource_id)

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

def _temporal_resource_state(record: dict[str, Any], category: str) -> str:
    """Return a state transition only for explicit, recognized state values."""
    fields = {str(k).casefold(): v for k, v in record.items()}
    if category == "flow":
        raw = fields.get("enabled", fields.get("status", fields.get("state", "")))
        value = _norm_id(raw).upper()
        if value in {"TRUE", "1", "YES", "ENABLED", "ACTIVE", "RUNNING"}:
            return "ACTIVE"
        if value in {"FALSE", "0", "NO", "DISABLED", "INACTIVE", "STOPPED", "PAUSED"}:
            return "DISABLED"
    if category == "backup":
        raw = fields.get("restorable", fields.get("restore_allowed", fields.get("restore_state", fields.get("status", ""))))
        value = _norm_id(raw).upper()
        if value in {"TRUE", "1", "YES", "RESTORABLE", "ENABLED", "ACTIVE", "ALLOWED"}:
            return "ACTIVE"
        if value in {"FALSE", "0", "NO", "BLOCKED", "NOT_RESTORABLE", "DISABLED", "DENIED", "RESTORE_BLOCKED"}:
            return "BLOCKED"
    for key in ("deletion_state", "record_state", "resulting_state", "state", "status"):
        value = _norm_id(fields.get(key)).upper().replace("-", "_").replace(" ", "_")
        if value in {"ABSENT", "DELETED", "REMOVED", "PURGED", "NOT_FOUND", "NONEXISTENT", "NON_EXISTENT"}:
            return "ABSENT"
        if value in {"REDACTED", "REDACTION_COMPLETE"}:
            return "REDACTED"
        if value in {"ANONYMIZED", "ANONYMISED", "DEIDENTIFIED", "DE_IDENTIFIED"}:
            return "ANONYMIZED"
        if value in {"PRESENT", "EXISTS", "EXISTING", "LIVE", "RETAINED"}:
            return "PRESENT"
    return ""


def _resource_observation_time(record: dict[str, Any], captured_at: datetime) -> datetime:
    """Use explicit event/effective time; otherwise use known snapshot capture time."""
    for key in ("event_time", "event_timestamp", "occurred_at", "effective_at",
                "status_at", "observed_at", "timestamp"):
        raw = record.get(key)
        if raw is not None and str(raw).strip():
            return normalize_timestamp(str(raw))
    return normalize_timestamp(captured_at)


def classify_resources(hits:list[EvidenceHit],users:set[str],aliases:set[str],tokens:set[str],cutoff:datetime|None=None)->list[Resource]:
    found: dict[tuple[str, str, str], Resource] = {}
    found_order: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    temporal_events: dict[tuple[str, str], list[TemporalEvent]] = {}
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
                    if cutoff is not None:
                        eligible, _temporal_reason = observation_is_eligible(rec, captured_at=hit.captured_at, audit_at=cutoff)
                        if not eligible:
                            continue
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
                        enabled = str(fields.get("enabled", fields.get("status", fields.get("state", "")))).casefold()
                        sysid = str(rec.get("system_id") or store or "integration_service")
                        if enabled in {"true", "1", "enabled", "active", "running"}:
                            op, state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                        else:
                            resource_state = _temporal_resource_state(rec, category)
                            if resource_state:
                                observed_at = _resource_observation_time(rec, hit.captured_at)
                                temporal_events.setdefault((sysid, rid), []).append(TemporalEvent(
                                    f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                                    hit.file_id, hit.path, "SUPPORTED",
                                    f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                                ))
                            continue
                    elif category == "backup":
                        restorable = str(fields.get("restorable", fields.get("restore_allowed", fields.get("status", "")))).casefold()
                        sysid = str(rec.get("system_id") or store or "backup_service")
                        if restorable in {"true", "1", "yes", "restorable", "enabled", "active"}:
                            op, state = "REPORT_RESTORE_RISK", "ACTIVE"
                        else:
                            resource_state = _temporal_resource_state(rec, category)
                            if resource_state:
                                observed_at = _resource_observation_time(rec, hit.captured_at)
                                temporal_events.setdefault((sysid, rid), []).append(TemporalEvent(
                                    f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                                    hit.file_id, hit.path, "SUPPORTED",
                                    f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                                ))
                            continue
                    elif category == "analytics":
                        op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", str(rec.get("data_store") or store or "analytics_platform")
                    elif category == "support":
                        op, state, sysid = "REPORT_EXPOSED_PII", "PRESENT", str(rec.get("data_store") or store or "support_platform")
                    else:
                        op, state, sysid = "REPORT_REMAINING_RECORD", "PRESENT", str(rec.get("data_store") or store or infer_system(path, rid))
                    key = (sysid, rid, op)
                    observed_at = _resource_observation_time(rec, hit.captured_at)
                    order_key = (observed_at, hit.file_id)
                    if key not in found_order or order_key > found_order[key]:
                        found[key] = Resource(sysid, rid, op, state, hit.file_id)
                        found_order[key] = order_key
                    resource_state = _temporal_resource_state(rec, category)
                    if resource_state:
                        timeline_key = (sysid, rid)
                        temporal_events.setdefault(timeline_key, []).append(TemporalEvent(
                            f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                            hit.file_id, hit.path, "SUPPORTED",
                            f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                        ))
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
                if cutoff is not None:
                    eligible, _temporal_reason = observation_is_eligible(rec, captured_at=hit.captured_at, audit_at=cutoff)
                    if not eligible:
                        continue
                # Newer replicas serialize the original customer record inside a SQL
                # text column. Unpack that payload before exact identity matching.
                for payload_key in ("record_json", "payload", "document"):
                    payload = rec.get(payload_key)
                    if not payload:
                        continue
                    try:
                        nested = json.loads(payload)
                    except (json.JSONDecodeError, TypeError):
                        nested = None
                    if isinstance(nested, dict):
                        rec = {**rec, **{str(k).casefold(): v for k, v in nested.items()}}
                if cutoff is not None:
                    eligible, _temporal_reason = observation_is_eligible(rec, captured_at=hit.captured_at, audit_at=cutoff)
                    if not eligible:
                        continue
                if not (_contains_subject(rec, aliases, tokens, users) or _record_matches(rec, aliases, users)):
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
                elif category == "flow":
                    sysid = infer_system(path, rid)
                    resource_state = _temporal_resource_state(rec, category)
                    if resource_state == "ACTIVE":
                        op, state = "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
                    else:
                        if resource_state:
                            observed_at = _resource_observation_time(rec, hit.captured_at)
                            temporal_events.setdefault((sysid, rid), []).append(TemporalEvent(
                                f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                                hit.file_id, hit.path, "SUPPORTED",
                                f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                            ))
                        continue
                elif category == "backup":
                    sysid = infer_system(path, rid)
                    resource_state = _temporal_resource_state(rec, category)
                    if resource_state == "ACTIVE":
                        op, state = "REPORT_RESTORE_RISK", "ACTIVE"
                    else:
                        if resource_state:
                            observed_at = _resource_observation_time(rec, hit.captured_at)
                            temporal_events.setdefault((sysid, rid), []).append(TemporalEvent(
                                f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                                hit.file_id, hit.path, "SUPPORTED",
                                f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                            ))
                        continue
                else:
                    op, state, sysid = "REPORT_REMAINING_RECORD", "PRESENT", infer_system(path, rid)
                key = (sysid, rid, op)
                observed_at = _resource_observation_time(rec, hit.captured_at)
                order_key = (observed_at, hit.file_id)
                if key not in found_order or order_key > found_order[key]:
                    found[key] = Resource(sysid, rid, op, state, hit.file_id)
                    found_order[key] = order_key
                resource_state = _temporal_resource_state(rec, category)
                if resource_state:
                    timeline_key = (sysid, rid)
                    temporal_events.setdefault(timeline_key, []).append(TemporalEvent(
                        f"{sysid}:{rid}", observed_at, resource_state, "RESOURCE_OBSERVATION",
                        hit.file_id, hit.path, "SUPPORTED",
                        f"Observed {resource_state} in {hit.file_id} at {observed_at.isoformat()}",
                    ))
                structured = True
        if structured:
            continue
        # Text evidence: parse each row/line and attach only the evidence identifier
        # that was captured by the manifest before the case's audit cutoff.
        for line_no, line in enumerate(hit.text.splitlines(), start=1):
            if cutoff is not None:
                # Text logs commonly encode timestamp=... or event_time=...; malformed
                # explicit timestamps are not silently treated as current state.
                temporal_fields = dict(re.findall(r"(?i)(event_time|event_timestamp|occurred_at|effective_at|status_at|observed_at|timestamp)\s*[=:]\s*([^,;| ]+)", line))
                if temporal_fields:
                    eligible, _temporal_reason = observation_is_eligible(temporal_fields, captured_at=hit.captured_at, audit_at=cutoff)
                    if not eligible:
                        continue
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
                key = (sysid, rid, op)
                found[key] = Resource(sysid, rid, op, state, hit.file_id)
                found_order[key] = (_resource_observation_time({}, hit.captured_at), hit.file_id)
    if cutoff is not None:
        # A later explicit state supersedes a stale positive snapshot for that resource.
        # Contradictory same-instant states remain uncertain, so findings are retained.
        suppress: set[str] = set()
        for (sysid, rid), events in temporal_events.items():
            result = reconstruct_state(f"{sysid}:{rid}", events, cutoff)
            if result.certainty != "SUPPORTED":
                continue
            if result.state == "ABSENT":
                suppress.add(f"{sysid}\\0{rid}\\0ALL")
            elif result.state in {"REDACTED", "ANONYMIZED"}:
                suppress.add(f"{sysid}\\0{rid}\\0REPORT_EXPOSED_PII")
            elif result.state == "DISABLED":
                suppress.add(f"{sysid}\\0{rid}\\0REPORT_ACTIVE_DATA_FLOW")
            elif result.state == "BLOCKED":
                suppress.add(f"{sysid}\\0{rid}\\0REPORT_RESTORE_RISK")
        found = {
            key: resource for key, resource in found.items()
            if f"{resource.system_id}\\0{resource.resource_id}\\0ALL" not in suppress
            and f"{resource.system_id}\\0{resource.resource_id}\\0{resource.operation}" not in suppress
        }
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
    resources = classify_resources(hits, users, aliases, tokens, cutoff=cutoff)
    resources.extend(_activity_resources(case, data, users, aliases, cutoff))
    plan = build_plan(resources)

    # A clean result requires explicit negative-state evidence for the account and
    # any policy-relevant retained resources. The positive-evidence scanner does not
    # have enough information to assert COMPLETE by itself.
    return "INCOMPLETE", plan

def _validate_steps(steps: list[dict[str, Any]], case_id: str) -> None:
    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    last_phase = -1
    for i, step in enumerate(steps, 1):
        if not isinstance(step, dict) or list(step) != STEP_FIELDS:
            raise InputError(f"Invalid step schema for {case_id} at position {i}")
        if step["step_no"] != i:
            raise InputError(f"Invalid step numbering for {case_id}")
        if (step["phase"], step["operation"], step["state"]) not in ALLOWED:
            raise InputError(f"Invalid operation/state for {case_id}: {step}")
        rank = phase_order[step["phase"]]
        if rank < last_phase:
            raise InputError(f"Invalid phase order for {case_id}")
        last_phase = rank
        if step["phase"] == "FINDING" and not step["evidence_id"]:
            raise InputError(f"Finding must cite evidence for {case_id}")
        if step["phase"] != "FINDING" and step["evidence_id"]:
            raise InputError(f"Proposed future action must not cite existing evidence for {case_id}")
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
        if row["deletion_status"]=="COMPLETE" and (not steps or any(s["phase"]!="VERIFICATION" or not s["evidence_id"] for s in steps)): raise InputError("COMPLETE requires non-empty, evidence-backed verification-only steps")
        _validate_steps(steps, row["case_id"])

def generate(dataset:Path,output:Path,requests_file:Path|None=None)->dict[str,Any]:
    data=load_inputs(dataset,requests_file); results=[]
    evidence_index=EvidenceIndex(dataset).build()
    for diagnostic in evidence_index.diagnostics:
        print(f"[evidence:{diagnostic.code}] {diagnostic.file_id} {diagnostic.path}: {diagnostic.message}", file=sys.stderr)
    evidence_cache=[
        EvidenceHit(doc.file_id,doc.file_path,doc.captured_at,doc.text)
        for doc in evidence_index.documents.values() if doc.status=="INDEXED"
    ]
    evidence_cache.sort(key=lambda h:(h.captured_at,h.file_id,h.path))
    for case in data["requests"]:
        cutoff=parse_time(case["audit_at"])
        case_evidence=[hit for hit in evidence_cache if hit.captured_at<=cutoff]
        status,steps=audit_case(case,data,dataset,case_evidence)
        results.append({"case_id":case["case_id"],"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))})
    valid_ids=evidence_index.manifest_ids()
    activity_ids={str(row.get("activity_id","")).strip() for row in data["activity"]}
    for row in results:
        for step in json.loads(row["steps_json"]):
            if step["phase"]=="FINDING" and step["evidence_id"] not in valid_ids|activity_ids:
                raise InputError(f"Finding cites unknown evidence ID {step['evidence_id']!r} in {row['case_id']}")
    results.sort(key=lambda r:r["case_id"]); validate_output(results,{r["case_id"] for r in data["requests"]})
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("w",encoding="utf-8",newline="") as f:
        writer=csv.DictWriter(f,fieldnames=OUTPUT_FIELDS,lineterminator="\n"); writer.writeheader(); writer.writerows(results)
    return {"rows":len(results),"statuses":{s:sum(x["deletion_status"]==s for x in results) for s in sorted(STATUSES)},"output":str(output),
            "evidence_index":evidence_index.stats()}


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
