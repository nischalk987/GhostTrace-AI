import unittest
from datetime import datetime, timezone, timedelta

from temporal_state import (
    TemporalEvent, event_from_mapping, normalize_timestamp,
    observation_is_eligible, reconstruct_state,
)

class TemporalStateTests(unittest.TestCase):
    def event(self, time, state, *, key="r1", evidence="ev", order=""):
        return TemporalEvent(key, normalize_timestamp(time), state, "STATE_CHANGE", evidence, order)

    def test_normalizes_offsets_and_naive_timestamp(self):
        self.assertEqual(
            normalize_timestamp("2026-01-01T01:00:00+01:00"),
            normalize_timestamp("2026-01-01T00:00:00Z"),
        )
        self.assertEqual(
            normalize_timestamp("2026-01-01T00:00:00"),
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )

    def test_event_at_cutoff_is_included_and_after_is_excluded(self):
        cutoff = "2026-01-02T00:00:00Z"
        before = self.event("2026-01-01T00:00:00Z", "PRESENT", evidence="before")
        exact = self.event(cutoff, "ABSENT", evidence="exact")
        future = self.event("2026-01-02T00:00:00.000001Z", "PRESENT", evidence="future")
        result = reconstruct_state("r1", [future, exact, before], cutoff)
        self.assertEqual(result.state, "ABSENT")
        self.assertEqual([e.evidence_id for e in result.included], ["before", "exact"])
        self.assertEqual([e.evidence_id for e in result.excluded], ["future"])

    def test_out_of_order_input_is_deterministic(self):
        events = [
            self.event("2026-01-03T00:00:00Z", "ABSENT", evidence="b"),
            self.event("2026-01-01T00:00:00Z", "PRESENT", evidence="a"),
            self.event("2026-01-02T00:00:00Z", "REDACTED", evidence="c"),
        ]
        first = reconstruct_state("r1", events, "2026-01-04T00:00:00Z")
        second = reconstruct_state("r1", list(reversed(events)), "2026-01-04T00:00:00Z")
        self.assertEqual(first, second)
        self.assertEqual(first.state, "ABSENT")

    def test_conflicting_same_time_events_are_unknown_not_last_write_wins(self):
        same = "2026-01-01T00:00:00Z"
        result = reconstruct_state("r1", [
            self.event(same, "PRESENT", evidence="a"),
            self.event(same, "ABSENT", evidence="b"),
        ], "2026-01-02T00:00:00Z")
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(result.certainty, "CONFLICTING")
        self.assertIn("Conflicting states", result.explanation)

    def test_identical_same_time_state_is_supported_and_provenance_kept(self):
        same = "2026-01-01T00:00:00Z"
        result = reconstruct_state("r1", [
            self.event(same, "PRESENT", evidence="b"),
            self.event(same, "PRESENT", evidence="a"),
        ], "2026-01-02T00:00:00Z")
        self.assertEqual(result.state, "PRESENT")
        self.assertEqual(result.evidence_ids, ("a", "b"))

    def test_missing_or_malformed_timestamp_is_not_replaced_with_now(self):
        eligible, diagnostic = event_from_mapping(
            {"resource_id": "r1", "state": "ABSENT"}, evidence_id="ev1",
            captured_at="2026-01-01T00:00:00Z", audit_at="2026-01-02T00:00:00Z")
        self.assertIsNone(eligible)
        self.assertIn("missing", diagnostic)
        malformed, diagnostic = event_from_mapping(
            {"resource_id": "r1", "state": "ABSENT", "event_time": "tomorrow-ish"},
            evidence_id="ev1", captured_at="2026-01-01T00:00:00Z",
            audit_at="2026-01-02T00:00:00Z")
        self.assertIsNone(malformed)
        self.assertIn("malformed", diagnostic)

    def test_evidence_capture_after_cutoff_excluded_even_if_event_is_earlier(self):
        parsed, diagnostic = event_from_mapping(
            {"resource_id":"r1","state":"ABSENT","event_time":"2026-01-01T00:00:00Z"},
            evidence_id="late", captured_at="2026-01-03T00:00:00Z",
            audit_at="2026-01-02T00:00:00Z")
        self.assertIsNone(parsed)
        self.assertIn("captured after", diagnostic)

    def test_observation_gate_respects_explicit_event_time_and_boundary(self):
        cutoff = "2026-01-02T00:00:00Z"
        self.assertTrue(observation_is_eligible(
            {"event_time": cutoff}, captured_at="2026-01-01T00:00:00Z",
            audit_at=cutoff)[0])
        self.assertFalse(observation_is_eligible(
            {"event_time":"2026-01-03T00:00:00Z"},
            captured_at="2026-01-01T00:00:00Z", audit_at=cutoff)[0])
        self.assertFalse(observation_is_eligible(
            {"event_time":"bad timestamp"},
            captured_at="2026-01-01T00:00:00Z", audit_at=cutoff)[0])

    def test_no_supported_event_produces_unknown(self):
        result = reconstruct_state("r1", [], "2026-01-02T00:00:00Z")
        self.assertEqual(result.state, "UNKNOWN")
        self.assertEqual(result.certainty, "INSUFFICIENT")

if __name__ == "__main__":
    unittest.main()
