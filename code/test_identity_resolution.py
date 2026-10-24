import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from identity_resolution import IdentityResolver, normalize_identifier

class IdentityResolutionTests(unittest.TestCase):
    def resolver(self):
        identities = [
            {"user_id":"u1","email":"New@Example.com ","phone":"+1 (202) 555-0100","email_hash":"hash-a","updated_at":"2026-01-02T00:00:00Z"},
            {"user_id":"u2","email":"other@example.com","phone":"+1 202 555 0100","email_hash":"hash-b","updated_at":"2026-01-02T00:00:00Z"},
        ]
        audit = [
            {"audit_id":"a1","user_id":"u1","event_time":"2025-12-01T00:00:00Z","field_name":"email","old_value":"old@example.com","new_value":"New@Example.com"},
            {"audit_id":"a2","user_id":"u2","event_time":"2026-01-03T00:00:00Z","field_name":"email","old_value":"reused@example.com","new_value":"other@example.com"},
            {"audit_id":"a3","user_id":"u1","event_time":"2026-02-03T00:00:00Z","field_name":"email","old_value":"old@example.com","new_value":"third@example.com"},
        ]
        return IdentityResolver(identities, audit)

    def test_current_email_normalization_and_trace(self):
        result = self.resolver().resolve_subject("  NEW@example.COM ", "2026-01-10T00:00:00Z")
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.user_id, "u1")
        self.assertTrue(result.matches)
        self.assertTrue(any(m.source_file == "user_identities.csv" and m.source_row == 2 for m in result.matches))

    def test_historical_email_resolves_with_audit_provenance(self):
        result = self.resolver().resolve_subject("old@example.com", "2026-02-01T00:00:00Z")
        self.assertEqual(result.status, "RESOLVED")
        self.assertEqual(result.user_id, "u1")
        self.assertTrue(any(m.source_id == "a1" and m.reason.startswith("historical") for m in result.matches))

    def test_reused_identifier_is_ambiguous(self):
        resolver = IdentityResolver(
            [{"user_id":"u1","email":"current1@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"},
             {"user_id":"u2","email":"current2@example.com","phone":"","email_hash":"","updated_at":"2026-01-01T00:00:00Z"}],
            [{"audit_id":"a1","user_id":"u1","event_time":"2025-01-01T00:00:00Z","field_name":"email","old_value":"shared@example.com","new_value":"current1@example.com"},
             {"audit_id":"a2","user_id":"u2","event_time":"2025-02-01T00:00:00Z","field_name":"email","old_value":"shared@example.com","new_value":"current2@example.com"}])
        result = resolver.resolve_subject("shared@example.com", "2026-03-01T00:00:00Z")
        self.assertEqual(result.status, "AMBIGUOUS")
        self.assertIsNone(result.user_id)
        self.assertEqual(result.candidates, ("u1", "u2"))

    def test_future_evidence_is_excluded(self):
        self.assertEqual(self.resolver().resolve_subject("third@example.com", "2026-02-01T00:00:00Z").status, "UNRESOLVED")

    def test_unknown_or_missing_cutoff_is_explicit(self):
        resolver = self.resolver()
        self.assertEqual(resolver.resolve_subject("nobody@example.com", "2026-03-01T00:00:00Z").status, "UNRESOLVED")
        self.assertEqual(resolver.resolve_subject("old@example.com").status, "UNRESOLVED")

    def test_email_normalization_preserves_meaningful_distinctions(self):
        self.assertEqual(normalize_identifier(" A+B@Example.com ", "email"), "a+b@example.com")
        self.assertNotEqual(normalize_identifier("a.b@example.com"), normalize_identifier("ab@example.com"))
        self.assertNotEqual(normalize_identifier("a+b@example.com"), normalize_identifier("a@example.com"))

    def test_phone_formatting_keeps_country_code(self):
        self.assertEqual(normalize_identifier("+1 (202) 555-0100", "phone"), normalize_identifier("+1 202 555 0100", "phone"))
        self.assertNotEqual(normalize_identifier("+1 202 555 0100", "phone"), normalize_identifier("202 555 0100", "phone"))

    def test_request_object_api(self):
        self.assertTrue(self.resolver().resolve_subject({"email":"new@example.com","audit_at":"2026-01-10T00:00:00Z"}).resolved)

if __name__ == "__main__":
    unittest.main()
