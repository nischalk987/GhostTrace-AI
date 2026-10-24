import csv, json, tempfile, unittest
from datetime import timezone
from pathlib import Path

from main import (
    InputError, Resource, _walk_records, build_plan, identity_aliases,
    parse_time, request_authorizes_deletion, read_evidence, validate_output,
)

class EngineRegressionTests(unittest.TestCase):
    def test_request_intent(self):
        self.assertTrue(request_authorizes_deletion("Please permanently delete my account."))
        self.assertFalse(request_authorizes_deletion("Please send me an export of my data."))
        self.assertFalse(request_authorizes_deletion("Do not delete my account."))

    def test_historical_email_alias_respects_cutoff(self):
        identities = [{"user_id":"u1","name":"A","email":"new@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"}]
        audit = [
            {"user_id":"u1","field_name":"email","old_value":"old@example.com","new_value":"new@example.com","event_time":"2026-01-01T00:00:00Z"},
            {"user_id":"u1","field_name":"email","old_value":"new@example.com","new_value":"future@example.com","event_time":"2026-02-01T00:00:00Z"},
        ]
        users, aliases = identity_aliases("old@example.com", identities, audit, parse_time("2026-01-15T00:00:00Z"))
        self.assertEqual(users, {"u1"})
        self.assertIn("new@example.com", aliases)
        self.assertNotIn("future@example.com", aliases)

    def test_ambiguous_reused_email_does_not_mix_subjects(self):
        identities = [
            {"user_id":"u1","name":"A","email":"current1@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"},
            {"user_id":"u2","name":"B","email":"current2@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"},
        ]
        audit = [
            {"audit_id":"a1","user_id":"u1","field_name":"email","old_value":"shared@example.com","new_value":"current1@example.com","event_time":"2025-01-01T00:00:00Z"},
            {"audit_id":"a2","user_id":"u2","field_name":"email","old_value":"shared@example.com","new_value":"current2@example.com","event_time":"2025-02-01T00:00:00Z"},
        ]
        users, aliases = identity_aliases("shared@example.com", identities, audit, parse_time("2026-03-01T00:00:00Z"))
        self.assertEqual(users, set())
        self.assertEqual(aliases, set())

    def test_evidence_after_cutoff_is_excluded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "before.txt").write_text("before", encoding="utf-8")
            (root / "after.txt").write_text("after", encoding="utf-8")
            manifest = [
                {"file_id":"e1","file_path":"before.txt","captured_at":"2026-01-01T00:00:00Z"},
                {"file_id":"e2","file_path":"after.txt","captured_at":"2026-02-01T00:00:00Z"},
            ]
            hits = read_evidence(root, manifest, parse_time("2026-01-15T00:00:00Z"))
            self.assertEqual([h.file_id for h in hits], ["e1"])

    def test_manifest_scanner_validates_paths_and_reports_broken_files(self):
        from evidence_index import EvidenceIndex
        with tempfile.TemporaryDirectory() as td:
            dataset = Path(td) / "dataset"
            (dataset / "evidence" / "records").mkdir(parents=True)
            (dataset / "evidence" / "records" / "sample.json").write_text(
                '{"resource_id":"search_1","email":"a@example.com"}', encoding="utf-8")
            (dataset / "evidence_files.csv").write_text(
                "file_id,file_path,origin,captured_at\n"
                "ev1,evidence/records/sample.json,manifest-hint,2026-01-01T00:00:00Z\n"
                "ev2,../outside.json,manifest-hint,2026-01-01T00:00:00Z\n"
                "ev3,evidence/records/missing.json,manifest-hint,2026-01-01T00:00:00Z\n",
                encoding="utf-8")
            index = EvidenceIndex(dataset).build()
            self.assertTrue(index.query_subject("email", "a@example.com"))
            codes = {d.code for d in index.diagnostics}
            self.assertIn("UNSAFE_PATH", codes)
            self.assertIn("MISSING_FILE", codes)
            self.assertEqual(index.documents["ev1"].status, "INDEXED")

    def test_nested_record_json_is_parsed(self):
        rows = list(_walk_records({"data_store":"analytics_platform","records":[
            {"resource_id":"analytics_9","record_json":json.dumps({"resource_id":"analytics_9","email":"a@b.com"})}
        ]}))
        self.assertTrue(any(row.get("email") == "a@b.com" for row, _, _ in rows))

    def test_plan_has_findings_remediation_verification_order(self):
        plan = build_plan([
            Resource("search_service","search_1","REPORT_REMAINING_RECORD","PRESENT","e1"),
            Resource("backup_service","backup_1","REPORT_RESTORE_RISK","ACTIVE","e2"),
        ])
        phase_rank = {"FINDING":0,"REMEDIATION":1,"VERIFICATION":2}
        phases = [phase_rank[s["phase"]] for s in plan]
        self.assertEqual(phases, sorted(phases))
        self.assertTrue(all(s["evidence_id"] for s in plan if s["phase"] == "FINDING"))
        self.assertTrue(all(not s["evidence_id"] for s in plan if s["phase"] != "FINDING"))

    def test_output_rejects_invalid_status(self):
        with self.assertRaises(InputError):
            validate_output([{"case_id":"case_1","deletion_status":"UNKNOWN","steps_json":"[]"}], {"case_1"})

    def test_output_rejects_out_of_order_phases(self):
        rows = [{
            "case_id": "case_1",
            "deletion_status": "INCOMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
                {"step_no": 2, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_1"},
            ]),
        }]
        with self.assertRaises(InputError):
            validate_output(rows, {"case_1"})

    def test_output_rejects_evidence_on_proposed_action(self):
        rows = [{
            "case_id": "case_1",
            "deletion_status": "INCOMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "REMEDIATION", "system_id": "account_service", "resource_id": "account_1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": "evidence_1"},
            ]),
        }]
        with self.assertRaises(InputError):
            validate_output(rows, {"case_1"})

if __name__ == "__main__":
    unittest.main()
