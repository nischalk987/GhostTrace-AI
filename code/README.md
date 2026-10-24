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

## Manifest-backed evidence index

The reusable `code/evidence_index.py` index validates every manifest path beneath `dataset/evidence/`, parses JSON/CSV/SQLite-compatible SQL and text/log records once per run, and records source provenance (evidence ID, source path, source line/row, timestamp, system/resource IDs, subject identifiers, and SHA-256). Missing, corrupt, unsafe, duplicate, unreadable, and unsupported items are surfaced as stderr diagnostics. PDF and image files are inventoried but are not used as evidence until an OCR adapter is configured; filenames and manifest labels are never proof.

Standalone tests:

```bash
python -m unittest discover -s code -p "test_evidence_index.py" -v
```


## Historical state reconstruction

`code/temporal_state.py` provides UTC timestamp normalization and deterministic state reconstruction as of a request's `audit_at`. Event time (for ordering a state transition), evidence capture time (when an artifact was collected), request time, reported workflow time, and audit cutoff remain distinct. Events or evidence captured after the cutoff are excluded; explicit malformed event timestamps are rejected rather than replaced with the current time. At the latest event instant, conflicting state claims return `UNKNOWN` with `CONFLICTING` certainty and a provenance/explanation chain instead of silently choosing whichever row was read last. The production resource classifier also gates structured rows and text/log lines by explicit event timestamps.

Temporal-specific tests:

```bash
python -m unittest discover -s code -p "test_temporal_state.py" -v
```
