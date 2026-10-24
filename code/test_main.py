import csv, json, tempfile, unittest
from datetime import timezone
from pathlib import Path

from main import (
    InputError, Resource, _walk_records, build_plan, identity_aliases,
    parse_time, request_authorizes_deletion, read_evidence, validate_output, classify_resources, EvidenceHit, evaluate_record_policy, validate_step_sequence,
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
            (root / "evidence").mkdir()
            (root / "evidence" / "before.txt").write_text("before", encoding="utf-8")
            (root / "evidence" / "after.txt").write_text("after", encoding="utf-8")
            manifest = [
                {"file_id":"e1","file_path":"evidence/before.txt","captured_at":"2026-01-01T00:00:00Z"},
                {"file_id":"e2","file_path":"evidence/after.txt","captured_at":"2026-02-01T00:00:00Z"},
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


    def test_resource_classifier_excludes_future_and_malformed_record_events(self):
        from datetime import datetime, timezone
        future = EvidenceHit(
            "e-future", "evidence/records/future.json",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            json.dumps({"resource_id": "search_future", "email": "a@example.com",
                        "event_time": "2026-02-01T00:00:00Z"})
        )
        malformed = EvidenceHit(
            "e-bad", "evidence/records/bad.json",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            json.dumps({"resource_id": "search_bad", "email": "a@example.com",
                        "event_time": "not-a-time"})
        )
        cutoff = parse_time("2026-01-15T00:00:00Z")
        resources = classify_resources([future, malformed], {"u1"}, {"a@example.com"},
                                       {"a@example.com"}, cutoff=cutoff)
        self.assertEqual(resources, [])

    def test_resource_classifier_includes_event_exactly_at_cutoff(self):
        from datetime import datetime, timezone
        hit = EvidenceHit(
            "e-boundary", "evidence/records/boundary.json",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            json.dumps({"resource_id": "search_boundary", "email": "a@example.com",
                        "event_time": "2026-01-15T00:00:00Z"})
        )
        resources = classify_resources([hit], {"u1"}, {"a@example.com"},
                                       {"a@example.com"}, cutoff=parse_time("2026-01-15T00:00:00Z"))
        self.assertTrue(any(r.resource_id == "search_boundary" for r in resources))


    def test_later_absent_snapshot_supersedes_older_positive_snapshot(self):
        from datetime import datetime, timezone
        old = EvidenceHit(
            "ev-old", "evidence/records/search_snapshot.json",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            json.dumps({"resource_id":"search_1","email":"a@example.com",
                        "state":"PRESENT","event_time":"2026-01-01T00:00:00Z"})
        )
        new = EvidenceHit(
            "ev-new", "evidence/records/search_snapshot.json",
            datetime(2026, 1, 3, tzinfo=timezone.utc),
            json.dumps({"resource_id":"search_1","email":"a@example.com",
                        "state":"ABSENT","event_time":"2026-01-03T00:00:00Z"})
        )
        cutoff = parse_time("2026-01-04T00:00:00Z")
        resources = classify_resources([new, old], {"u1"}, {"a@example.com"},
                                       {"a@example.com"}, cutoff=cutoff)
        self.assertEqual(resources, [])

    def test_conflicting_same_time_state_keeps_conservative_finding(self):
        from datetime import datetime, timezone
        t = datetime(2026, 1, 1, tzinfo=timezone.utc)
        present = EvidenceHit(
            "ev-a", "evidence/records/search_snapshot.json", t,
            json.dumps({"resource_id":"search_1","email":"a@example.com",
                        "state":"PRESENT","event_time":"2026-01-01T00:00:00Z"})
        )
        absent = EvidenceHit(
            "ev-b", "evidence/records/search_snapshot.json", t,
            json.dumps({"resource_id":"search_1","email":"a@example.com",
                        "state":"ABSENT","event_time":"2026-01-01T00:00:00Z"})
        )
        resources = classify_resources([present, absent], {"u1"}, {"a@example.com"},
                                       {"a@example.com"}, cutoff=parse_time("2026-01-02T00:00:00Z"))
        self.assertTrue(any(r.resource_id == "search_1" for r in resources))



    def test_policy_rules_loaded_and_validated_at_input_load(self):
        from main import validate_policy_inputs
        rules = [
            {"rule_id":"r1","data_category":"USER_PROFILE","condition":"Always","required_action":"DELETE"}
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "deletion_rules.csv").write_text(
                "rule_id,data_category,condition,required_action\nr1,USER_PROFILE,Always,DELETE\n",
                encoding="utf-8"
            )
            validate_policy_inputs(root, rules)
            with self.assertRaises(InputError):
                validate_policy_inputs(root, rules + rules)

    def test_build_plan_does_not_delete_retained_security_or_backup_records(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rules.csv"
            p.write_text(
                "rule_id,data_category,condition,required_action\n"
                "rsec,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN\n"
                "rbackup,BACKUP_ARCHIVE,Restore access can be blocked,RETAIN\n",
                encoding="utf-8"
            )
            resources = [
                Resource("security_service", "audit_record_1", "REPORT_REMAINING_RECORD", "PRESENT", "ev1"),
                Resource("backup_service", "backup_1", "REPORT_REMAINING_RECORD", "PRESENT", "ev2"),
                Resource("search_service", "search_1", "REPORT_REMAINING_RECORD", "PRESENT", "ev3"),
            ]
            plan = build_plan(resources, policy_path=p)
            finding_ids = {(x["system_id"], x["resource_id"]) for x in plan if x["phase"] == "FINDING"}
            self.assertNotIn(("security_service", "audit_record_1"), finding_ids)
            self.assertNotIn(("backup_service", "backup_1"), finding_ids)
            self.assertIn(("search_service", "search_1"), finding_ids)
            self.assertTrue(any(x["operation"] == "DELETE_RECORD" and x["resource_id"] == "search_1" for x in plan))

    def test_tombstone_direct_identifiers_are_not_treated_as_safe_redaction(self):
        from deletion_policy import DeletionPolicy
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rules.csv"
            p.write_text(
                "rule_id,data_category,condition,required_action\n"
                "r1,ACCOUNT_TOMBSTONE,Account is deleted and only a stable internal user_id is needed to preserve references to retained records,REDACT\n",
                encoding="utf-8"
            )
            policy = DeletionPolicy.from_csv(p)
            record = {
                "resource_id":"tombstone_1", "user_id":"u1",
                "account_deleted":True, "stable_user_id_required":True,
                "email":"still-visible@example.com",
            }
            decision = evaluate_record_policy(record, "evidence/tombstone.json", "", "tombstone_1", policy)
            self.assertEqual(decision.action, "UNRESOLVED")
            self.assertIn("TOMBSTONE_REDACTION_REQUIRED", decision.diagnostics)

    def test_legal_hold_record_is_retained_when_active_hold_is_explicit(self):
        from deletion_policy import DeletionPolicy
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "rules.csv"
            p.write_text(
                "rule_id,data_category,condition,required_action\nr1,LEGAL_HOLD_RECORD,A supplied legal hold is active,RETAIN\n",
                encoding="utf-8"
            )
            policy = DeletionPolicy.from_csv(p)
            decision = policy.decide("LEGAL_HOLD_RECORD", {"legal_hold_active": True})
            self.assertEqual(decision.action, "RETAIN")
            self.assertFalse(decision.safe_to_delete)


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
