"""Time-aware reconstruction of evidence-backed resource state.

Timestamps are never defaulted to the wall clock. Evidence capture, the request,
workflow report, and audit cutoff are separate clocks; only event/effective time
orders state transitions, and only evidence captured by audit_at may be used.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

# Only these fields describe when a state/event became effective. Capture time is
# intentionally excluded: it describes when evidence was collected, not the event.
EVENT_TIME_FIELDS = (
    "event_time", "event_timestamp", "occurred_at", "effective_at",
    "status_at", "observed_at", "timestamp",
)
STATE_FIELDS = ("state", "status", "record_state", "resulting_state")
EVENT_FIELDS = ("event_type", "operation", "action", "event", "type")

def normalize_timestamp(value: str | datetime) -> datetime:
    """Return a UTC-aware instant; naive ISO timestamps are explicitly interpreted as UTC."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid ISO-8601 timestamp: {value!r}") from exc
    else:
        raise ValueError(f"Missing timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def _first(row: Mapping[str, Any], keys: Iterable[str]) -> Any:
    folded = {str(k).casefold(): v for k, v in row.items()}
    for key in keys:
        value = folded.get(key)
        if value is not None and str(value).strip():
            return value
    return None

@dataclass(frozen=True)
class TemporalEvent:
    resource_key: str
    event_time: datetime
    state: str
    event_type: str
    evidence_id: str
    source_order: str = ""
    confidence: str = "SUPPORTED"
    explanation: str = ""

@dataclass(frozen=True)
class StateReconstruction:
    resource_key: str
    state: str
    certainty: str
    as_of: datetime
    included: tuple[TemporalEvent, ...]
    excluded: tuple[TemporalEvent, ...]
    explanation: str

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(e.evidence_id for e in self.included if e.evidence_id))

def event_from_mapping(
    row: Mapping[str, Any], *, evidence_id: str, captured_at: str | datetime,
    audit_at: str | datetime, default_resource_key: str = "",
    source_order: str = "",
) -> tuple[TemporalEvent | None, str | None]:
    """Parse one event without conflating its event time with capture/audit time.

    Returns (event, diagnostic). Missing or malformed event time is not guessed.
    Events captured after audit_at are rejected even when their event timestamp is old.
    """
    try:
        cutoff = normalize_timestamp(audit_at)
        captured = normalize_timestamp(captured_at)
    except ValueError as exc:
        return None, f"invalid cutoff/capture timestamp: {exc}"
    if captured > cutoff:
        return None, "evidence was captured after audit_at"
    raw_time = _first(row, EVENT_TIME_FIELDS)
    if raw_time is None:
        return None, "event timestamp is missing; state transition is uncertain"
    try:
        event_time = normalize_timestamp(str(raw_time))
    except ValueError as exc:
        return None, f"malformed event timestamp; state transition is uncertain: {exc}"
    if event_time > cutoff:
        return None, "event occurred after audit_at"
    resource = _first(row, ("resource_id", "record_id", "object_id", "account_id", "id"))
    event_type = _first(row, EVENT_FIELDS) or "OBSERVATION"
    state = _first(row, STATE_FIELDS) or ""
    key = str(resource or default_resource_key).strip()
    if not key:
        return None, "resource identifier is missing; event cannot be joined safely"
    return TemporalEvent(
        key, event_time, str(state).strip().upper(), str(event_type).strip().upper(),
        str(evidence_id).strip(), source_order,
        "SUPPORTED" if state else "UNCERTAIN",
        f"{event_type} at {event_time.isoformat()} from {evidence_id or 'unreferenced evidence'}",
    ), None

def reconstruct_state(
    resource_key: str,
    events: Iterable[TemporalEvent],
    audit_at: str | datetime,
) -> StateReconstruction:
    """Reconstruct state deterministically at the cutoff with explicit tie handling.

    Later events are excluded. At an identical instant, multiple distinct states
    are contradictory and produce UNKNOWN rather than arbitrary last-write-wins.
    Identical state ties are retained in stable provenance order. A malformed or
    missing timestamp cannot be represented as a TemporalEvent; the parser reports it.
    """
    cutoff = normalize_timestamp(audit_at)
    all_events = [e for e in events if e.resource_key == resource_key]
    eligible = [e for e in all_events if normalize_timestamp(e.event_time) <= cutoff]
    future = [e for e in all_events if normalize_timestamp(e.event_time) > cutoff]
    eligible.sort(key=lambda e: (
        normalize_timestamp(e.event_time), e.source_order, e.evidence_id,
        e.event_type, e.state, e.explanation,
    ))
    future.sort(key=lambda e: (
        normalize_timestamp(e.event_time), e.source_order, e.evidence_id,
        e.event_type, e.state, e.explanation,
    ))
    if not eligible:
        reason = "No supported event at or before audit_at; state is unknown."
        if future:
            reason += f" Excluded {len(future)} future event(s)."
        return StateReconstruction(resource_key, "UNKNOWN", "INSUFFICIENT", cutoff,
                                   (), tuple(future), reason)
    latest_time = normalize_timestamp(eligible[-1].event_time)
    latest = [e for e in eligible if normalize_timestamp(e.event_time) == latest_time]
    supported_states = {e.state for e in latest if e.state}
    if any(e.confidence != "SUPPORTED" or not e.state for e in latest) or not supported_states:
        state, certainty = "UNKNOWN", "INSUFFICIENT"
        reason = f"Latest event(s) at {latest_time.isoformat()} lack a supported state."
    elif len(supported_states) > 1:
        state, certainty = "UNKNOWN", "CONFLICTING"
        reason = (f"Conflicting states at identical event time {latest_time.isoformat()}: "
                  f"{', '.join(sorted(supported_states))}; no arbitrary tie-break was applied.")
    else:
        state, certainty = next(iter(supported_states)), "SUPPORTED"
        reason = f"State {state} is supported by the latest event time {latest_time.isoformat()}."
    included = tuple(eligible)
    excluded = tuple(future)
    reason += f" Included {len(included)} event(s); excluded {len(excluded)} event(s) after audit_at."
    return StateReconstruction(resource_key, state, certainty, cutoff, included, excluded, reason)

def observation_is_eligible(
    row: Mapping[str, Any], *, captured_at: str | datetime,
    audit_at: str | datetime,
) -> tuple[bool, str]:
    """Gate a snapshot/history row by evidence capture and any explicit event time.

    Rows without any explicit event timestamp are snapshot observations: their
    manifest capture time is the observation time. A present-but-malformed event
    timestamp is not silently replaced with capture/current time.
    """
    try:
        cutoff = normalize_timestamp(audit_at)
        captured = normalize_timestamp(captured_at)
    except ValueError as exc:
        return False, f"invalid capture/cutoff timestamp: {exc}"
    if captured > cutoff:
        return False, "evidence capture is after audit_at"
    raw = _first(row, EVENT_TIME_FIELDS)
    if raw is None:
        return True, "snapshot eligible by evidence capture time"
    try:
        event_time = normalize_timestamp(str(raw))
    except ValueError:
        return False, "explicit event timestamp is malformed"
    if event_time > cutoff:
        return False, "explicit event timestamp is after audit_at"
    return True, "event and evidence capture are at or before audit_at"
