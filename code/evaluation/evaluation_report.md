# Evaluation report

## Current status
Contract tests cover request intent, allowed step shape, evidence-required findings, malformed input schema, and case coverage validation. Run:
```bash
python -m unittest discover -s code -p "test_*.py" -v
python code/main.py --validate-only
```

The implementation has not yet been validated for exact equivalence to `dataset/sample_output.csv`. Case-level status accuracy, step/field accuracy and sequence accuracy are therefore **not measured**; do not interpret prediction counts as accuracy.

## Custom test cases
1. “Please permanently delete my account.” must classify as a deletion request.
2. “Please send me a copy of my data.” must classify as NOT_APPLICABLE.
3. Evidence manifest entry captured after audit_at must be ignored.
4. A tombstone with non-empty name/email/phone/email_hash must create an exposed-PII finding.
5. Missing required CSV columns must fail with a clear error.

## Failures and next improvements
- PDF/image evidence needs a tested extraction layer.
- SQL data rows and per-category conditions need full structured parsing rather than line heuristics.
- The sample output comparator and case/step/field/sequence metrics remain to be implemented.
- Add explicit proof rules for retained security/legal records, tombstone compliance, disabled flows and blocked restores.
