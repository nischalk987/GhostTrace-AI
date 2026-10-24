# GhostTrace deletion audit engine

## Run

Python 3.10+; standard library only. From repository root:

```bash
python code/main.py --validate-only
python code/main.py --dataset dataset --output output.csv
python -m unittest discover -s code -p "test_*.py" -v
python code/evaluate.py --dataset dataset
```

The engine validates input schemas, resolves current and historical email aliases as of `audit_at`, ignores evidence manifest items captured after each case cutoff, parses nested JSON records and SQLite-compatible SQL INSERT rows, and writes the required output schema. Findings cite evidence IDs; proposed future actions have empty evidence IDs.

## Evaluation

`code/evaluate.py` compares the generated sample predictions to `dataset/sample_output.csv`. It reports status accuracy, exact step-array accuracy, per-step field accuracy, and sequence accuracy. Schema validation alone is not an accuracy measurement.

## Known limits

The engine is deterministic and has no model/API cost. PDF/image screenshots are not yet OCR-parsed; legal-hold and retention rules need subject-specific extraction from source documents. The engine does not assert `COMPLETE` from absence of positive evidence alone. Treat outputs as a baseline until sample metrics and remaining evidence adapters are reviewed.
