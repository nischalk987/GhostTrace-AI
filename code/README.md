# GhostTrace deletion audit engine

## Run
Python 3.10+; standard library only. From repo root:

```bash
python code/main.py --validate-only
python code/main.py --dataset dataset --output output.csv
python -m unittest discover -s code -p "test_*.py" -v
```

The command validates input schemas, resolves current and historical email aliases, filters evidence using manifest capture timestamps and each case's audit cutoff, and emits validated JSON steps.

## Current limitations
This is an initial deterministic baseline, not yet a canonical-accuracy submission. The built-in extractor handles text, JSON and SQL lines but does not OCR PDFs/screenshots or fully interpret database schemas and policy-specific retention windows. In ambiguous cases, it avoids marking a request COMPLETE without explicit compliant-state verification. Complete the multimodal and record-level evidence parser and run sample-output evaluation before relying on predictions.
