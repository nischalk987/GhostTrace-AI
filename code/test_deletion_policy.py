import csv
import tempfile
import unittest
from pathlib import Path

from deletion_policy import (
    ALLOWED_ACTIONS, DeletionPolicy, PolicyError, PolicyRule, record_policy_category,
)

RULES = """rule_id,data_category,condition,required_action
r_profile,USER_PROFILE,Always,DELETE
r_support,SUPPORT_MESSAGE,"Conversation contains shared customer agent or order context that must be retained",REDACT
r_attachment,SUPPORT_ATTACHMENT,Attachment belongs only to the deletion subject,DELETE
r_analytics,ANALYTICS_PROFILE,Record is still attributable to a user,ANONYMIZE
r_telemetry,PRODUCT_TELEMETRY,Record is still attributable to a user,ANONYMIZE
r_export,USER_EXPORT,Always,DELETE
r_email,EMAIL_DELIVERY_LOG,Log contains a user email address,REDACT
r_security,SECURITY_AUDIT_LOG,Record is within the supplied retention period,RETAIN
r_hold,LEGAL_HOLD_RECORD,A supplied legal hold is active,RETAIN
r_backup,BACKUP_ARCHIVE,Restore access can be blocked,RETAIN
r_tombstone,ACCOUNT_TOMBSTONE,"Account is deleted and only a stable internal user_id is needed to preserve references to retained records",REDACT
"""

class DeletionPolicyTests(unittest.TestCase):
    def policy(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        p = Path(temp.name) / "rules.csv"
        p.write_text(RULES, encoding="utf-8")
        return DeletionPolicy.from_csv(p)

    def test_validates_rule_schema_ids_categories_and_actions(self):
        policy = self.policy()
        self.assertEqual(len(policy.rules), 11)
        self.assertTrue(all(r.required_action in ALLOWED_ACTIONS for r in policy.rules))
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.csv"
            p.write_text("rule_id,data_category,condition,required_action\nr1,UNLISTED,Always,DELETE\n", encoding="utf-8")
            with self.assertRaises(PolicyError):
                DeletionPolicy.from_csv(p)

    def test_unconditional_delete_applies(self):
        decision = self.policy().decide("USER_PROFILE")
        self.assertEqual(decision.action, "DELETE")
        self.assertEqual(decision.rule_ids, ("r_profile",))
        self.assertTrue(decision.safe_to_delete)

    def test_shared_support_redacts_when_explicitly_retained(self):
        decision = self.policy().decide("SUPPORT_MESSAGE", {"shared_context_must_be_retained": True})
        self.assertEqual(decision.action, "REDACT")
        self.assertIn("r_support", decision.rule_ids)

    def test_attachment_rule_is_conditional(self):
        policy = self.policy()
        self.assertEqual(policy.decide("SUPPORT_ATTACHMENT", {}).action, "UNRESOLVED")
        self.assertEqual(policy.decide("SUPPORT_ATTACHMENT", {"belongs_only_to_subject": True}).action, "DELETE")
        self.assertEqual(policy.decide("SUPPORT_ATTACHMENT", {"belongs_only_to_subject": False}).action, "NOT_APPLICABLE")

    def test_analytics_and_telemetry_require_attribution(self):
        policy = self.policy()
        self.assertEqual(policy.decide("ANALYTICS_PROFILE", {"still_attributable": True}).action, "ANONYMIZE")
        self.assertEqual(policy.decide("PRODUCT_TELEMETRY", {"still_attributable": False}).action, "NOT_APPLICABLE")
        self.assertEqual(policy.decide("ANALYTICS_PROFILE", {}).action, "UNRESOLVED")

    def test_email_and_security_retention_conditions(self):
        policy = self.policy()
        self.assertEqual(policy.decide("EMAIL_DELIVERY_LOG", {"contains_user_email": True}).action, "REDACT")
        self.assertEqual(policy.decide("SECURITY_AUDIT_LOG", {"within_retention_period": True}).action, "RETAIN")
        self.assertEqual(policy.decide("SECURITY_AUDIT_LOG", {"within_retention_period": False}).action, "NOT_APPLICABLE")

    def test_legal_hold_prevents_delete_without_active_hold_evidence(self):
        policy = self.policy()
        self.assertEqual(policy.decide("LEGAL_HOLD_RECORD", {"legal_hold_active": True}).action, "RETAIN")
        self.assertEqual(policy.decide("LEGAL_HOLD_RECORD", {}).action, "UNRESOLVED")

    def test_backup_retained_when_restore_can_be_blocked(self):
        decision = self.policy().decide("BACKUP_ARCHIVE", {"restore_access_can_be_blocked": True})
        self.assertEqual(decision.action, "RETAIN")
        self.assertFalse(decision.safe_to_delete)

    def test_tombstone_requires_both_deletion_and_stable_reference(self):
        policy = self.policy()
        self.assertEqual(policy.decide("ACCOUNT_TOMBSTONE", {"account_deleted": True}).action, "UNRESOLVED")
        decision = policy.decide("ACCOUNT_TOMBSTONE", {
            "account_deleted": True, "stable_user_id_required": True
        })
        self.assertEqual(decision.action, "REDACT")
        self.assertFalse(decision.safe_to_delete)

    def test_conflicting_rules_retain_wins_with_diagnostic(self):
        policy = DeletionPolicy([
            PolicyRule("a", "USER_PROFILE", "Always", "DELETE"),
            PolicyRule("b", "USER_PROFILE", "Always", "RETAIN"),
        ])
        decision = policy.decide("USER_PROFILE")
        self.assertEqual(decision.action, "RETAIN")
        self.assertIn("RETENTION_PRECEDENCE", decision.diagnostics)
        self.assertEqual(decision.rule_ids, ("a", "b"))

    def test_contradiction_without_safe_precedence_is_unresolved(self):
        policy = DeletionPolicy([
            PolicyRule("a", "USER_PROFILE", "Always", "ANONYMIZE"),
            PolicyRule("b", "USER_PROFILE", "Always", "DELETE"),
        ])
        decision = policy.decide("USER_PROFILE")
        self.assertEqual(decision.action, "UNRESOLVED")
        self.assertTrue(decision.diagnostics[0].startswith("CONTRADICTORY"))

    def test_category_mapping_specificity(self):
        self.assertEqual(record_policy_category("evidence/legal_hold_record.json"), "LEGAL_HOLD_RECORD")
        self.assertEqual(record_policy_category("evidence/tombstones/account.json"), "ACCOUNT_TOMBSTONE")
        self.assertEqual(record_policy_category("evidence/logs/email_delivery.log"), "EMAIL_DELIVERY_LOG")
        self.assertEqual(record_policy_category("evidence/analytics/profile.json"), "ANALYTICS_PROFILE")
        self.assertEqual(record_policy_category("evidence/unknown/records.json"), "SECONDARY_IDENTIFIER")

    def test_unknown_categories_never_authorize_deletion(self):
        decision = self.policy().decide("UNKNOWN_CATEGORY", {})
        self.assertEqual(decision.action, "UNRESOLVED")
        self.assertFalse(decision.safe_to_delete)

if __name__ == "__main__":
    unittest.main()
