# Evaluation report

## Running the regression checks

From the repository root:

```bash
python -m unittest discover -s code -p "test_*.py" -v
python code/evaluate.py --dataset dataset
python code/main.py --validate-only
```

The evaluator compares generated output on the 32 sample requests with `dataset/sample_output.csv` and prints:
- case-level deletion status accuracy;
- exact ordered `steps_json` array accuracy;
- step/field accuracy; and
- phase/operation sequence accuracy.

Do not treat schema validation as proof of canonical accuracy. Run the evaluator and preserve its actual metrics with the submission.

## Additional regression cases

1. A historical email change after `audit_at` must not add a future alias.
2. An evidence manifest entry captured after `audit_at` must be excluded.
3. An export/download request must return `NOT_APPLICABLE` and `[]`.
4. A support conversation shared with another customer must be retained and redacted according to the supplied rule.
5. A tombstone with direct identifiers populated must produce an exposed-PII finding.

## Current limitations

- Screenshot/PDF evidence needs OCR with validation against the source; unsupported claims are not inferred.
- Legal-hold and retention evidence requires subject-specific extraction and rule application.
- The engine does not assert `COMPLETE` from an empty findings list alone.
