# Manifest-backed evidence index

The `EvidenceIndex` reads `dataset/evidence_files.csv` once and caches extracted facts for reuse across deletion requests. It uses manifest paths only to locate files; paths are constrained to `dataset/evidence/`, validated against traversal and symlink escapes, and checked for duplicate IDs/paths.

## Supported content
- JSON: recursively extracts explicit fields and nested records.
- CSV: extracts row/field facts.
- SQL/SQLite text dumps: executes in an isolated in-memory SQLite database and extracts actual rows, not comments or arbitrary string fragments.
- TXT/log/Markdown: extracts explicit key/value fields and preserves line context.
- PDF/image: reports a diagnostic and leaves content unparsed until an OCR adapter is configured. These files are not treated as proof from filename or manifest origin.

Every fact retains the evidence `file_id`, path, capture time, SHA-256 content hash, source line/row, system/resource identifiers, subject identifiers, and parsed event time when available. Diagnostics report missing, corrupt, unsafe, duplicate, unreadable, and unsupported items.

## Example
```python
from code.evidence_index import EvidenceIndex

index = EvidenceIndex("dataset").build()
matches = index.query_subject("email", "person@example.com", cutoff="2026-09-15T00:00:00Z")
for fact in matches:
    print(fact.file_id, fact.file_path, fact.field_name, fact.value, fact.source_line)
print(index.stats(), index.diagnostics)
```

This index is deterministic and reusable. It does not infer case membership from filenames, manifest origins, or reported statuses.
