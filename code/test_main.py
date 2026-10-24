import tempfile, unittest
from pathlib import Path
from main import InputError, STEP_FIELDS, ALLOWED, make_step, request_authorizes_deletion, read_csv, validate_output

class EngineContractTests(unittest.TestCase):
    def test_deletion_intent(self):
        self.assertTrue(request_authorizes_deletion("Please permanently delete my account."))
        self.assertTrue(request_authorizes_deletion("Je demande la suppression définitive du compte."))
        self.assertTrue(request_authorizes_deletion("このアカウントの削除を依頼します。"))
        self.assertFalse(request_authorizes_deletion("Please send me a copy of my data."))
        self.assertFalse(request_authorizes_deletion("Do not delete the account; just update my email."))
    def test_step_schema_and_allowed_operation(self):
        step=make_step(1,"FINDING","search_service","search_1","REPORT_REMAINING_RECORD","PRESENT","evidence_01")
        self.assertEqual(list(step),STEP_FIELDS)
        self.assertIn((step["phase"],step["operation"],step["state"]),ALLOWED)
    def test_finding_requires_evidence(self):
        with self.assertRaises(InputError):
            make_step(1,"FINDING","search_service","search_1","REPORT_REMAINING_RECORD","PRESENT","")
    def test_missing_output_row_rejected(self):
        with self.assertRaises(InputError):
            validate_output([{"case_id":"case_01","deletion_status":"NOT_APPLICABLE","steps_json":"[]"}],{"case_01","case_02"})
    def test_bad_schema_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"input.csv"; path.write_text("case_id\ncase_01\n",encoding="utf-8")
            with self.assertRaises(InputError): read_csv(path,["case_id","email"])

if __name__=="__main__": unittest.main()
