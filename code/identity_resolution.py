"""Evidence-backed identity resolution across current and historical identifiers."""
from __future__ import annotations
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

def normalize_identifier(value: str | None, field_name: str = "email") -> str:
    """Normalize harmless formatting; preserve provider-specific email distinctions."""
    value = (value or "").strip()
    kind = field_name.casefold()
    if kind == "email":
        return value.casefold()
    if kind == "phone":
        return "".join(ch for ch in value if ch.isdigit() or ch == "+")
    return value.casefold()

def _parse_time(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        try:
            result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)

@dataclass(frozen=True)
class IdentityMatch:
    user_id: str
    identifier_type: str
    matched_value: str
    reason: str
    source_file: str
    source_row: int
    source_id: str
    event_time: str

@dataclass(frozen=True)
class ResolutionResult:
    status: str
    query_identifier: str
    normalized_identifier: str
    user_id: str | None
    candidates: tuple[str, ...] = ()
    matches: tuple[IdentityMatch, ...] = ()
    warnings: tuple[str, ...] = ()
    @property
    def resolved(self) -> bool:
        return self.status == "RESOLVED" and self.user_id is not None

@dataclass(frozen=True)
class _Record:
    user_id: str
    field_name: str
    value: str
    normalized: str
    event_time: datetime
    source_file: str
    source_row: int
    source_id: str
    reason: str

class IdentityResolver:
    """CSV-backed index retaining exact provenance for every identity match."""
    def __init__(self, identities: Iterable[Mapping[str, str]], audit_log: Iterable[Mapping[str, str]],
                 identity_path: str = "user_identities.csv", audit_path: str = "user_audit_log.csv"):
        self.records: list[_Record] = []
        self.warnings: list[str] = []
        self._add_current(identities, identity_path)
        self._add_audit(audit_log, audit_path)
        self.index: dict[tuple[str, str], list[_Record]] = {}
        for record in self.records:
            self.index.setdefault((record.field_name, record.normalized), []).append(record)
        for records in self.index.values():
            records.sort(key=lambda x: (x.event_time, x.user_id, x.source_row, x.source_id))

    @staticmethod
    def _read_csv(path: str | Path, required: set[str]) -> list[dict[str, str]]:
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Identity input does not exist: {path}")
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                raise ValueError(f"Identity CSV has no header: {path}")
            missing = required.difference(reader.fieldnames)
            if missing:
                raise ValueError(f"{path}: missing columns {', '.join(sorted(missing))}")
            rows = list(reader)
        if not rows:
            raise ValueError(f"Identity CSV has no data rows: {path}")
        return rows

    @classmethod
    def from_csv(cls, identities_path: str | Path, audit_path: str | Path) -> "IdentityResolver":
        id_path, au_path = Path(identities_path), Path(audit_path)
        identities = cls._read_csv(id_path, {"user_id", "name", "email", "phone", "email_hash", "updated_at"})
        audit = cls._read_csv(au_path, {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"})
        return cls(identities, audit, str(id_path), str(au_path))

    def _add_current(self, rows: Iterable[Mapping[str, str]], filename: str) -> None:
        for n, row in enumerate(rows, start=2):
            user = (row.get("user_id") or "").strip()
            when = (row.get("updated_at") or "").strip()
            if not user or not when:
                self.warnings.append(f"{filename}:{n}: missing user_id or updated_at")
                continue
            try:
                timestamp = _parse_time(when)
            except ValueError:
                self.warnings.append(f"{filename}:{n}: invalid updated_at")
                continue
            for field in ("email", "phone", "email_hash"):
                value = (row.get(field) or "").strip()
                norm = normalize_identifier(value, field)
                if norm:
                    self.records.append(_Record(user, field, value, norm, timestamp, filename, n, "",
                                                 f"current {field} snapshot"))

    def _add_audit(self, rows: Iterable[Mapping[str, str]], filename: str) -> None:
        for n, row in enumerate(rows, start=2):
            user = (row.get("user_id") or "").strip()
            when = (row.get("event_time") or "").strip()
            field = (row.get("field_name") or "").strip().casefold()
            if not user or not when or field not in {"email", "phone", "email_hash"}:
                continue
            try:
                timestamp = _parse_time(when)
            except ValueError:
                self.warnings.append(f"{filename}:{n}: invalid event_time")
                continue
            source_id = (row.get("audit_id") or "").strip()
            for column, reason in (("old_value", "historical previous value in identity audit"),
                                   ("new_value", "historical replacement value in identity audit")):
                value = (row.get(column) or "").strip()
                norm = normalize_identifier(value, field)
                if norm:
                    self.records.append(_Record(user, field, value, norm, timestamp, filename, n, source_id, reason))

    def resolve_subject(self, request: Mapping[str, str] | str, audit_at: str | datetime | None = None,
                        identifier_type: str = "email") -> ResolutionResult:
        """Resolve at an explicit cutoff; never guess when multiple subjects match."""
        if isinstance(request, str):
            query, cutoff_value = request, audit_at
        else:
            query = (request.get("identifier") or request.get("email") or "").strip()
            identifier_type = (request.get("identifier_type") or identifier_type).casefold()
            cutoff_value = audit_at or request.get("audit_at") or request.get("requested_at")
        query = (query or "").strip()
        normalized = normalize_identifier(query, identifier_type)
        if not normalized:
            return ResolutionResult("UNRESOLVED", query, normalized, None, warnings=("empty identifier",))
        if cutoff_value is None:
            return ResolutionResult("UNRESOLVED", query, normalized, None,
                                    warnings=("audit_at cutoff is required",))
        cutoff = _parse_time(cutoff_value)
        eligible = [r for r in self.index.get((identifier_type, normalized), []) if r.event_time <= cutoff]
        grouped: dict[str, list[IdentityMatch]] = {}
        for record in eligible:
            grouped.setdefault(record.user_id, []).append(IdentityMatch(
                record.user_id, record.field_name, record.value, record.reason, record.source_file,
                record.source_row, record.source_id, record.event_time.isoformat().replace("+00:00", "Z")
            ))
        candidates = tuple(sorted(grouped))
        matches = tuple(m for user in candidates for m in sorted(
            grouped[user], key=lambda x: (x.event_time, x.source_file, x.source_row, x.source_id, x.reason)))
        warnings = list(self.warnings)
        if len(candidates) > 1:
            status, user = "AMBIGUOUS", None
            warnings.append("identifier maps to multiple subjects by audit_at; no subject selected")
        elif len(candidates) == 1:
            status, user = "RESOLVED", candidates[0]
        else:
            status, user = "UNRESOLVED", None
            warnings.append("no matching identity evidence at or before audit_at")
        return ResolutionResult(status, query, normalized, user, candidates, matches, tuple(warnings))

def resolve_subject(request: Mapping[str, str] | str, identities_path: str | Path,
                    audit_path: str | Path, audit_at: str | datetime | None = None,
                    identifier_type: str = "email") -> ResolutionResult:
    """Convenience API for a single request."""
    return IdentityResolver.from_csv(identities_path, audit_path).resolve_subject(
        request, audit_at=audit_at, identifier_type=identifier_type)
