import tempfile
import unittest
from pathlib import Path
from evidence_index import EvidenceIndex


class EvidenceIndexTests(unittest.TestCase):
    def make_dataset(self, temp):
        root = Path(temp) / "dataset"
        (root / "evidence" / "records").mkdir(parents=True)
        (root / "evidence" / "logs").mkdir(parents=True)
        (root / "evidence" / "databases").mkdir(parents=True)
        (root / "evidence" / "images").mkdir(parents=True)
        (root / "evidence" / "records" / "one.json").write_text(
            '{"system_id":"search_service","records":[{"resource_id":"search_1","email":"A@B.COM","status":"PRESENT","event_time":"2026-01-01T00:00:00Z"}]}',
            encoding="utf-8")
        (root / "evidence" / "logs" / "one.log").write_text(
            'event_type=DELETE; user_id=user_1; resource_id=account_1; timestamp=2026-01-02T00:00:00Z; status=FAIL\n',
            encoding="utf-8")
        (root / "evidence" / "databases" / "one.sql").write_text(
            "CREATE TABLE records (resource_id TEXT, email TEXT, state TEXT); INSERT INTO records VALUES ('x_1','a@b.com','PRESENT');",
            encoding="utf-8")
        (root / "evidence" / "images" / "screen.png").write_bytes(b"fake image bytes")
        (root / "evidence" / "records" / "bad.json").write_text("{bad", encoding="utf-8")
        with (root / "evidence_files.csv").open("w", encoding="utf-8", newline="") as f:
            f.write("file_id,file_path,origin,captured_at\n")
            f.write("ev1,evidence/records/one.json,record-export,2026-01-01T00:00:00Z\n")
            f.write("ev2,evidence/logs/one.log,logs,2026-01-02T00:00:00Z\n")
            f.write("ev3,evidence/databases/one.sql,sql,2026-01-03T00:00:00Z\n")
            f.write("ev4,evidence/images/screen.png,screen,2026-01-04T00:00:00Z\n")
            f.write("ev5,evidence/records/bad.json,json,2026-01-05T00:00:00Z\n")
            f.write("ev6,../escape.txt,unknown,2026-01-01T00:00:00Z\n")
            f.write("ev7,evidence/records/missing.json,missing,2026-01-01T00:00:00Z\n")
        return root

    def test_indexes_structured_and_text_evidence_once(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            index = EvidenceIndex(root).build()
            self.assertTrue(index.query_subject("email", "a@b.com"))
            self.assertTrue(index.query_resource("search_1"))
            self.assertTrue(index.query_file("ev2"))
            self.assertEqual(index.documents["ev1"].status, "INDEXED")
            self.assertEqual(index.documents["ev3"].status, "INDEXED")
            self.assertEqual(index.documents["ev2"].status, "INDEXED")
            self.assertEqual(index.stats()["indexed_documents"], 3)

    def test_cutoff_and_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            index = EvidenceIndex(root).build()
            facts = index.query_subject("email", "a@b.com", "2026-01-02T00:00:00Z")
            self.assertTrue(facts)
            self.assertEqual(facts[0].file_id, "ev1")
            self.assertEqual(facts[0].file_path, "evidence/records/one.json")
            self.assertTrue(facts[0].content_hash)
            self.assertEqual(index.query_subject("email", "a@b.com", "2025-12-31T23:59:59Z"), [])

    def test_unsafe_missing_corrupt_and_binary_are_diagnosed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            index = EvidenceIndex(root).build()
            codes = {d.code for d in index.diagnostics}
            self.assertIn("UNSAFE_PATH", codes)
            self.assertIn("MISSING_FILE", codes)
            self.assertIn("CORRUPT_JSON", codes)
            self.assertIn("BINARY_TEXT_UNAVAILABLE", codes)
            self.assertEqual(index.documents["ev6"].status, "UNSAFE_PATH")

    def test_content_not_filename_or_origin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            # The image filename/origin contain no proof and no extracted facts.
            index = EvidenceIndex(root).build()
            self.assertEqual(index.query_file("ev4"), [])

    def test_build_is_idempotent_and_duplicate_safe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            index = EvidenceIndex(root).build()
            before = (len(index.facts), len(index.diagnostics))
            self.assertIs(index.build(), index)
            self.assertEqual(before, (len(index.facts), len(index.diagnostics)))
            self.assertEqual(len(index.query_resource("search_1")), len(set(
                (f.file_id, f.field_name, f.value, f.source_line, f.source_row) for f in index.query_resource("search_1")
            )))

    def test_sql_cannot_attach_external_databases(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.make_dataset(temp)
            external = Path(temp) / "outside.db"
            external.write_text("must remain unchanged", encoding="utf-8")
            sql_file = root / "evidence" / "databases" / "unsafe.sql"
            sql_file.write_text(
                "ATTACH DATABASE '" + str(external).replace("'", "''") + "' AS outside; "
                "CREATE TABLE local_data (email TEXT); INSERT INTO local_data VALUES ('a@example.com');",
                encoding="utf-8")
            manifest_path = root / "evidence_files.csv"
            with manifest_path.open("a", encoding="utf-8") as handle:
                handle.write("ev8,evidence/databases/unsafe.sql,sql,2026-01-06T00:00:00Z\n")
            index = EvidenceIndex(root).build()
            self.assertIn("SQL_PARSE_ERROR", {d.code for d in index.diagnostics})
            self.assertEqual(external.read_text(encoding="utf-8"), "must remain unchanged")

    def test_manifest_ids_are_used_for_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            index = EvidenceIndex(self.make_dataset(temp)).build()
            valid_ids = index.manifest_ids()
            self.assertIn("ev1", valid_ids)
            self.assertNotIn("ev6", valid_ids)
            self.assertNotIn("ev7", valid_ids)


if __name__ == "__main__":
    unittest.main()
