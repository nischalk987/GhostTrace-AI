# Evaluation report

## Regression evaluation

The sample set is the provided reference output (`dataset/sample_output.csv`). The current rules-based implementation has **not** been claimed as canonically accurate until a complete sample run is executed against the bundled dataset. Metrics must be produced by running the evaluator, not estimated manually.

Run from the repository root:

```bash
python -m unittest discover -s code -p "test_*.py" -v
python code/evaluate.py --dataset dataset --sample-only
python code/main.py --validate-only
```

The evaluator reports case/status accuracy, exact step-array accuracy, step-field accuracy, and sequence accuracy. It returns a failure code if the sample output differs from the reference output.

## Additional regression cases

1. **Historical identifier cutoff:** an email change after `audit_at` must not add the future alias to the subject.
2. **Future evidence cutoff:** a manifest item whose `captured_at` is after `audit_at` must not be used.
3. **Explicit no-deletion intent:** an export/download request must be `NOT_APPLICABLE` and have `steps_json=[]`.
4. **Shared support conversation:** preserve a shared conversation under policy and remediate identifying fields instead of deleting the entire record.
5. **Tombstone exposure:** a deleted-account tombstone with name, email, phone, or email hash still populated must produce a PII finding.

## Limitations

- PDF and screenshot evidence still requires OCR or a separately tested extraction adapter. No unverified OCR result is treated as fact.
- Retention/legal-hold documents need a subject-specific policy extraction step before they can drive a retained-record decision.
- The engine conservatively avoids asserting `COMPLETE` from the absence of a positive finding alone.
