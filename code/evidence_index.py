"""Manifest-backed evidence index with safe paths, deterministic extraction and provenance."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

SUPPORTED_TEXT = {".txt", ".log", ".json", ".csv", ".sql", ".md"}
SUPPORTED_BINARY = {".pdf", ".png", ".jpg", ".jpeg"}
IDENTITY_KEYS = {
    "user_id", "subject_reference", "customer_reference", "customer_id",
    "account_user_id", "owner_user_id", "email", "display_email", "old_email",
    "new_email", "customer_email", "requester_email", "owner_email", "email_hash",
    "phone", "name", "full_name", "display_name",
}
RESOURCE_KEYS = {"resource_id", "record_id", "id", "account_id", "ticket_id", "object_id"}
TIMESTAMP_KEYS = {"event_time", "timestamp", "created_at", "updated_at", "captured_at", "event_timestamp", "time"}
SYSTEM_KEYS = {"system_id", "source_system", "target_system", "data_store", "system", "service"}


def parse_timestamp(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def normalize_value(value: Any) -> str:
    return str(value).strip().casefold() if value is not None else ""


@dataclass(frozen=True)
class EvidenceDiagnostic:
    file_id: str
    path: str
    code: str
    message: str


@dataclass(frozen=True)
class EvidenceFact:
    fact_type: str
    value: str
    field_name: str
    file_id: str
    file_path: str
    captured_at: datetime
    source_line: int | None
    source_row: int | None
    system_id: str
    resource_id: str
    subject_identifiers: tuple[tuple[str, str], ...]
    event_time: datetime | None
    content_hash: str


@dataclass(frozen=True)
class EvidenceDocument:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime
    status: str
    content_hash: str = ""
    text: str = ""
    facts: tuple[EvidenceFact, ...] = ()


class EvidenceIndex:
    """Read a manifest once, inspect content, and expose queryable evidence facts.

    The index does not use filenames or manifest origins as proof. They provide
    storage location and context only; facts are emitted from parsed content.
    """

    def __init__(self, dataset_root: str | Path, manifest_path: str | Path | None = None):
        self.dataset_root = Path(dataset_root).resolve()
        self.manifest_path = Path(manifest_path).resolve() if manifest_path else self.dataset_root / "evidence_files.csv"
        self.documents: dict[str, EvidenceDocument] = {}
        self.facts: list[EvidenceFact] = []
        self.diagnostics: list[EvidenceDiagnostic] = []
        self._by_subject: dict[tuple[str, str], list[EvidenceFact]] = {}
        self._by_resource: dict[str, list[EvidenceFact]] = {}
        self._by_file: dict[str, list[EvidenceFact]] = {}
        self._built = False

    def build(self) -> "EvidenceIndex":
        if self._built:
            return self
        rows = self._read_manifest()
        seen_ids: set[str] = set()
        seen_paths: set[str] = set()
        for line_number, row in enumerate(rows, start=2):
            file_id = (row.get("file_id") or "").strip()
            raw_path = (row.get("file_path") or "").strip()
            origin = (row.get("origin") or "").strip()
            captured = (row.get("captured_at") or "").strip()
            if not file_id or not raw_path or not captured:
                self._diag(file_id, raw_path, "INVALID_MANIFEST_ROW", f"Manifest row {line_number} has empty required values")
                continue
            if file_id in seen_ids:
                self._diag(file_id, raw_path, "DUPLICATE_FILE_ID", f"Manifest row {line_number} duplicates file_id {file_id}")
                continue
            seen_ids.add(file_id)
            try:
                captured_at = parse_timestamp(captured)
            except ValueError as exc:
                self._diag(file_id, raw_path, "INVALID_CAPTURE_TIME", str(exc))
                continue
            safe_path, path_error = self._safe_path(raw_path)
            if path_error:
                self._diag(file_id, raw_path, "UNSAFE_PATH", path_error)
                self.documents[file_id] = EvidenceDocument(file_id, raw_path, origin, captured_at, "UNSAFE_PATH")
                continue
            relative = safe_path.relative_to(self.dataset_root).as_posix()
            if relative in seen_paths:
                self._diag(file_id, raw_path, "DUPLICATE_PATH", "Multiple manifest entries refer to the same resolved evidence path")
                continue
            seen_paths.add(relative)
            if not safe_path.is_file():
                self._diag(file_id, raw_path, "MISSING_FILE", f"Manifest target is missing: {relative}")
                self.documents[file_id] = EvidenceDocument(file_id, relative, origin, captured_at, "MISSING")
                continue
            suffix = safe_path.suffix.casefold()
            if suffix not in SUPPORTED_TEXT and suffix not in SUPPORTED_BINARY:
                self._diag(file_id, relative, "UNSUPPORTED_FORMAT", f"Unsupported evidence extension: {suffix or '(none)'}")
                self.documents[file_id] = EvidenceDocument(file_id, relative, origin, captured_at, "UNSUPPORTED")
                continue
            try:
                raw = safe_path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                if suffix in SUPPORTED_TEXT:
                    text_value = raw.decode("utf-8-sig", errors="strict")
                    facts = self._extract_text_facts(file_id, relative, captured_at, digest, suffix, text_value)
                    doc = EvidenceDocument(file_id, relative, origin, captured_at, "INDEXED", digest, text_value, tuple(facts))
                    self.facts.extend(facts)
                    for fact in facts:
                        self._by_file.setdefault(file_id, []).append(fact)
                        if fact.resource_id:
                            self._by_resource.setdefault(fact.resource_id.casefold(), []).append(fact)
                        for key, value in fact.subject_identifiers:
                            self._by_subject.setdefault((key, normalize_value(value)), []).append(fact)
                else:
                    self._diag(file_id, relative, "BINARY_TEXT_UNAVAILABLE",
                               "PDF/image content requires an OCR adapter; manifest and filename were not treated as evidence")
                    doc = EvidenceDocument(file_id, relative, origin, captured_at, "BINARY_UNPARSED", digest)
                self.documents[file_id] = doc
            except (OSError, UnicodeError, sqlite3.Error) as exc:
                self._diag(file_id, relative, "READ_OR_PARSE_ERROR", f"{type(exc).__name__}: {exc}")
                self.documents[file_id] = EvidenceDocument(file_id, relative, origin, captured_at, "ERROR")
        # Stable order makes query results reproducible independent of dict insertion details.
        self.facts.sort(key=lambda f: (f.captured_at, f.file_id, f.source_line or 0, f.source_row or 0,
                                       f.field_name, f.value, f.resource_id))
        for index in (self._by_subject, self._by_resource, self._by_file):
            for key in index:
                index[key].sort(key=lambda f: (f.captured_at, f.file_id, f.source_line or 0, f.source_row or 0, f.field_name))
        self._built = True
        return self

    def _read_manifest(self) -> list[dict[str, str]]:
        if not self.manifest_path.is_file():
            self._diag("", str(self.manifest_path), "MANIFEST_MISSING", "Evidence manifest does not exist")
            return []
        try:
            with self.manifest_path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                required = {"file_id", "file_path", "origin", "captured_at"}
                if not reader.fieldnames:
                    self._diag("", str(self.manifest_path), "MANIFEST_INVALID", "Manifest has no header")
                    return []
                missing = sorted(required.difference(reader.fieldnames))
                if missing:
                    self._diag("", str(self.manifest_path), "MANIFEST_INVALID", f"Missing columns: {', '.join(missing)}")
                    return []
                return list(reader)
        except (OSError, UnicodeError) as exc:
            self._diag("", str(self.manifest_path), "MANIFEST_READ_ERROR", f"{type(exc).__name__}: {exc}")
            return []

    def _safe_path(self, raw: str) -> tuple[Path | None, str | None]:
        normalized = raw.replace("\\", "/")
        candidate = Path(normalized)
        if candidate.is_absolute() or re.match(r"^[A-Za-z]:", normalized):
            # A manifest path may be evidence/... relative to dataset, or dataset/evidence/...
            if candidate.is_absolute():
                return None, "Absolute paths are not allowed"
            return None, "Drive-qualified paths are not allowed"
        parts = [p for p in normalized.split("/") if p not in {"", "."}]
        if not parts or any(p == ".." for p in parts):
            return None, "Empty or parent-traversal path is not allowed"
        if parts[0] == "dataset":
            parts = parts[1:]
        if not parts or parts[0] != "evidence":
            return None, "Evidence must resolve beneath dataset/evidence/"
        resolved = (self.dataset_root / Path(*parts)).resolve()
        expected_root = (self.dataset_root / "evidence").resolve()
        try:
            resolved.relative_to(expected_root)
        except ValueError:
            return None, "Resolved path escapes dataset/evidence/"
        return resolved, None

    def _diag(self, file_id: str, path: str, code: str, message: str) -> None:
        self.diagnostics.append(EvidenceDiagnostic(file_id, path, code, message))

    def _extract_text_facts(self, file_id: str, path: str, captured_at: datetime, digest: str,
                            suffix: str, content: str) -> list[EvidenceFact]:
        facts: list[EvidenceFact] = []
        if suffix == ".json":
            try:
                root = json.loads(content)
            except json.JSONDecodeError as exc:
                self._diag(file_id, path, "CORRUPT_JSON", f"JSON parse failed at line {exc.lineno}: {exc.msg}")
                return []
            self._walk_json(root, file_id, path, captured_at, digest, facts)
        elif suffix == ".csv":
            try:
                reader = csv.DictReader(content.splitlines())
                for row_num, row in enumerate(reader, start=2):
                    self._row_to_facts(row, file_id, path, captured_at, digest, None, row_num, facts)
            except csv.Error as exc:
                self._diag(file_id, path, "CORRUPT_CSV", str(exc))
        elif suffix == ".sql":
            self._extract_sql(content, file_id, path, captured_at, digest, facts)
        elif suffix in {".log", ".txt", ".md"}:
            for line_no, line in enumerate(content.splitlines(), start=1):
                self._extract_line_facts(line, file_id, path, captured_at, digest, line_no, facts)
        return facts

    def _walk_json(self, value: Any, file_id: str, path: str, captured_at: datetime, digest: str,
                   facts: list[EvidenceFact], parent: Mapping[str, Any] | None = None) -> None:
        if isinstance(value, dict):
            merged = dict(value)
            # Exact, explicit subject keys only. Do not inherit arbitrary text or PII from unrelated siblings.
            for k, v in (parent or {}).items():
                if str(k).casefold() in {"system_id", "data_store", "source_system", "target_system"} and not merged.get(k):
                    merged[k] = v
            self._row_to_facts(merged, file_id, path, captured_at, digest, None, None, facts)
            for child in value.values():
                if isinstance(child, (dict, list)):
                    self._walk_json(child, file_id, path, captured_at, digest, facts, merged)
                elif isinstance(child, str) and child[:1] in {"{", "["} and str(child).strip():
                    try:
                        parsed = json.loads(child)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(parsed, (dict, list)):
                        self._walk_json(parsed, file_id, path, captured_at, digest, facts, merged)
        elif isinstance(value, list):
            for child in value:
                self._walk_json(child, file_id, path, captured_at, digest, facts, parent)

    def _row_to_facts(self, row: Mapping[str, Any], file_id: str, path: str, captured_at: datetime,
                      digest: str, line: int | None, row_num: int | None, facts: list[EvidenceFact]) -> None:
        fields = {str(k).casefold(): v for k, v in row.items()}
        resource_id = next((str(fields[k]).strip() for k in RESOURCE_KEYS if fields.get(k) not in (None, "")), "")
        system_id = next((str(fields[k]).strip() for k in SYSTEM_KEYS if fields.get(k) not in (None, "")), "")
        event_time = None
        for key in TIMESTAMP_KEYS:
            if fields.get(key):
                try:
                    event_time = parse_timestamp(str(fields[key]))
                    break
                except ValueError:
                    continue
        subject = tuple(sorted((k, str(fields[k]).strip()) for k in IDENTITY_KEYS if fields.get(k) not in (None, "")))
        emitted: set[tuple[str, str, str]] = set()
        for key, value in sorted(fields.items()):
            if value in (None, ""):
                continue
            rendered = str(value).strip()
            if not rendered:
                continue
            if key in IDENTITY_KEYS:
                fact_type = "IDENTIFIER"
            elif key in RESOURCE_KEYS:
                fact_type = "RESOURCE"
            elif key in TIMESTAMP_KEYS:
                fact_type = "TIMESTAMP"
            elif key in SYSTEM_KEYS:
                fact_type = "SYSTEM"
            elif key in {"status", "state", "enabled", "active", "restorable", "restore_allowed", "operation", "event_type", "result"}:
                fact_type = "STATE_OR_EVENT"
            else:
                fact_type = "FIELD"
            dedupe_key = (key, normalize_value(rendered), fact_type)
            if dedupe_key in emitted:
                continue
            emitted.add(dedupe_key)
            facts.append(EvidenceFact(fact_type, rendered, key, file_id, path, captured_at, line, row_num,
                                      system_id, resource_id, subject, event_time, digest))

    def _extract_line_facts(self, line: str, file_id: str, path: str, captured_at: datetime,
                            digest: str, line_no: int, facts: list[EvidenceFact]) -> None:
        # Key-value tokens are extracted only when the line contains an actual value.
        pairs = re.findall(r"(?i)([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*([^,;|]+)", line)
        context = " ".join(line.split())
        if not pairs:
            # Preserve a source-line fact for traceability, but do not turn filenames into facts.
            if context:
                facts.append(EvidenceFact("TEXT_LINE", context, "_text", file_id, path, captured_at,
                                          line_no, None, "", "", (), None, digest))
            return
        normalized_pairs = {k.casefold(): v.strip().strip('"\' ') for k, v in pairs if v.strip().strip('"\' ')}
        row = dict(normalized_pairs)
        for key, value in row.items():
            if key in IDENTITY_KEYS | RESOURCE_KEYS | SYSTEM_KEYS | TIMESTAMP_KEYS:
                # A line can contain several explicit identifier fields and a resource/event.
                pass
        self._row_to_facts(row, file_id, path, captured_at, digest, line_no, None, facts)
        # Keep the original line as a separate fact so investigator can inspect context.
        if context:
            facts.append(EvidenceFact("TEXT_LINE", context, "_text", file_id, path, captured_at,
                                      line_no, None, "", str(row.get("resource_id") or row.get("id") or ""),
                                      tuple(sorted((k, str(v)) for k, v in row.items() if k in IDENTITY_KEYS)),
                                      None, digest))

    def _extract_sql(self, content: str, file_id: str, path: str, captured_at: datetime,
                     digest: str, facts: list[EvidenceFact]) -> None:
        # Parse plain SQL dump DDL/INSERTs using SQLite in a temporary in-memory DB.
        # This avoids matching string fragments in comments or malformed SQL.
        try:
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(content)
                for table_name, in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
                    quoted_table = '"' + table_name.replace('"', '""') + '"'
                    cursor = connection.execute(f"SELECT * FROM {quoted_table}")
                    columns = [description[0] for description in cursor.description or ()]
                    for row_num, values in enumerate(cursor.fetchall(), start=1):
                        row = dict(zip(columns, values))
                        self._row_to_facts(row, file_id, path, captured_at, digest, None, row_num, facts)
            finally:
                connection.close()
        except sqlite3.Error as exc:
            # Some dumps have non-SQLite syntax; preserve diagnostic instead of silently ignoring.
            self._diag(file_id, path, "SQL_PARSE_ERROR", f"{type(exc).__name__}: {exc}")

    def query_subject(self, identifier_type: str, identifier: str, cutoff: str | datetime | None = None) -> list[EvidenceFact]:
        self.build()
        if cutoff is not None:
            at = parse_timestamp(cutoff)
        else:
            at = None
        hits = self._by_subject.get((identifier_type.casefold(), normalize_value(identifier)), [])
        return [fact for fact in hits if at is None or fact.captured_at <= at]

    def query_resource(self, resource_id: str, cutoff: str | datetime | None = None) -> list[EvidenceFact]:
        self.build()
        at = parse_timestamp(cutoff) if cutoff is not None else None
        hits = self._by_resource.get(resource_id.casefold(), [])
        return [fact for fact in hits if at is None or fact.captured_at <= at]

    def query_file(self, file_id: str) -> list[EvidenceFact]:
        self.build()
        return list(self._by_file.get(file_id, []))

    def manifest_ids(self) -> set[str]:
        self.build()
        return {file_id for file_id, document in self.documents.items() if document.status not in {"MISSING", "UNSAFE_PATH"}}

    def stats(self) -> dict[str, int]:
        self.build()
        return {"documents": len(self.documents), "indexed_documents": sum(d.status == "INDEXED" for d in self.documents.values()),
                "facts": len(self.facts), "diagnostics": len(self.diagnostics),
                "unparsed_binary": sum(d.status == "BINARY_UNPARSED" for d in self.documents.values())}
