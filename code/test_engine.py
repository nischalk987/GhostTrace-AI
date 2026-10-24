import csv, io, json, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path

from main import (
    EvidenceHit, InputError, Resource, _walk_records, build_plan, classify_resources,
    identity_aliases, parse_time, request_authorizes_deletion, read_evidence,
    validate_output,
)

class AuditEngineRegressionTests(unittest.TestCase):
    def test_intent_negation_and_non_deletion(self):
        self.assertTrue(request_authorizes_deletion("Please permanently delete my account."))
        self.assertTrue(request_authorizes_deletion("Je demande la suppression définitive du compte."))
        self.assertTrue(request_authorizes_deletion("このアカウントの完全な削除を依頼します。"))
        self.assertTrue(request_authorizes_deletion("I was told the account had been deleted."))
        self.assertTrue(request_authorizes_deletion("Close this account permanently."))
        self.assertTrue(request_authorizes_deletion("Can you verify my account was deleted? Do not treat the similar search record as mine."))
        self.assertFalse(request_authorizes_deletion("Please export my data."))
        self.assertFalse(request_authorizes_deletion("Do not delete my account."))

    def test_historical_alias_is_cutoff_aware(self):
        identities = [{"user_id":"u1","name":"A","email":"new@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"}]
        audit = [
            {"user_id":"u1","field_name":"email","old_value":"old@example.com","new_value":"new@example.com","event_time":"2026-01-01T00:00:00Z"},
            {"user_id":"u1","field_name":"email","old_value":"new@example.com","new_value":"future@example.com","event_time":"2026-02-01T00:00:00Z"},
        ]
        users, aliases = identity_aliases("old@example.com", identities, audit, parse_time("2026-01-15T00:00:00Z"))
        self.assertEqual(users, {"u1"})
        self.assertIn("new@example.com", aliases)
        self.assertNotIn("future@example.com", aliases)

    def test_manifest_after_cutoff_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "before.txt").write_text("safe", encoding="utf-8")
            (root / "after.txt").write_text("future", encoding="utf-8")
            manifest = [
                {"file_id":"e1","file_path":"before.txt","captured_at":"2026-01-01T00:00:00Z"},
                {"file_id":"e2","file_path":"after.txt","captured_at":"2026-02-01T00:00:00Z"},
            ]
            hits = read_evidence(root, manifest, parse_time("2026-01-15T00:00:00Z"))
            self.assertEqual([h.file_id for h in hits], ["e1"])

    def test_walk_records_reads_record_json(self):
        rows = list(_walk_records({"data_store":"analytics_platform","records":[
            {"resource_id":"analytics_9","record_json":json.dumps({"resource_id":"analytics_9","email":"a@b.com"})}
        ]}))
        self.assertTrue(any(row.get("email") == "a@b.com" for row, _, _ in rows))

    def test_nested_subject_inherits_parent_resource_id(self):
        rows = list(_walk_records({"resource_id":"search_9","hits":{"documents":[
            {"email":"a@b.com","display_name":"A"}
        ]}}))
        self.assertTrue(any(row.get("resource_id")=="search_9" and row.get("email")=="a@b.com" for row, _, _ in rows))

    def test_build_plan_has_phase_order_and_empty_future_evidence(self):
        plan = build_plan([
            Resource("search_service","search_1","REPORT_REMAINING_RECORD","PRESENT","e1"),
            Resource("backup_service","backup_1","REPORT_RESTORE_RISK","ACTIVE","e2"),
        ])
        phases = [s["phase"] for s in plan]
        self.assertEqual(phases, sorted(phases, key={"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}.get))
        self.assertTrue(all(s["evidence_id"] for s in plan if s["phase"]=="FINDING"))
        self.assertTrue(all(not s["evidence_id"] for s in plan if s["phase"]!="FINDING"))

    def test_output_rejects_unknown_status_and_schema(self):
        with self.assertRaises(InputError):
            validate_output([{"case_id":"case_1","deletion_status":"MAYBE","steps_json":"[]"}], {"case_1"})

if __name__ == "__main__":
    unittest.main()
