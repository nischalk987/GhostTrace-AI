# Identity resolution module

Uses only Python's standard library to resolve a subject from current and historical identifiers, with source-row provenance and conservative ambiguity handling. The deletion engine invokes this resolver before collecting subject aliases; ambiguous or unknown identifiers yield no aliases and cannot merge unrelated users into one audit.

## API
```python
from identity_resolution import IdentityResolver
resolver = IdentityResolver.from_csv(
    "dataset/user_identities.csv",
    "dataset/user_audit_log.csv",
)
result = resolver.resolve_subject({"email": "old@example.com", "audit_at": "2026-09-01T00:00:00Z"})
if result.status == "RESOLVED":
    print(result.user_id, result.matches)
elif result.status == "AMBIGUOUS":
    print("Manual review required:", result.candidates)
else:
    print("Unresolved:", result.warnings)
```

Statuses are `RESOLVED`, `AMBIGUOUS`, and `UNRESOLVED`. Every positive match includes source filename, 1-based CSV row number, event timestamp, match reason, and `audit_id` when available. A cutoff is mandatory; future identity history is excluded. Email normalization trims whitespace and case-folds only—it does not remove dots or plus tags. Phone normalization removes punctuation but preserves a country-code prefix.

## Tests
Run from repository root:
```bash
python -m unittest discover -s code -p "test_identity_resolution.py" -v
```
