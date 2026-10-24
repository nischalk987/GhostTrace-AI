#!/usr/bin/env python3
"""Compare GhostTrace predictions with the bundled reference sample output."""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

FIELDS = ("case_id", "deletion_status", "steps_json")
STEP_FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")

def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != list(FIELDS):
            raise ValueError(f"{path}: expected columns {','.join(FIELDS)}")
        return list(reader)

def norm_steps(raw: str) -> list[dict]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("steps_json must be a JSON array")
    return value

def score(predicted: list[dict[str, str]], expected: list[dict[str, str]]) -> dict:
    by_id = {r["case_id"]: r for r in predicted}
    reference = {r["case_id"]: r for r in expected}
    if len(by_id) != len(predicted):
        raise ValueError("Predictions contain duplicate case IDs")
    if set(by_id) != set(reference):
        raise ValueError(f"Case coverage mismatch: predicted={len(by_id)}, expected={len(reference)}")
    n = len(reference)
    status_correct = sum(by_id[k]["deletion_status"] == reference[k]["deletion_status"] for k in reference)
    exact_steps = exact_sequences = matching_step_fields = 0
    total_expected_steps = total_pred_steps = 0
    for case_id, expected_row in reference.items():
        exp_steps = norm_steps(expected_row["steps_json"])
        pred_steps = norm_steps(by_id[case_id]["steps_json"])
        if pred_steps == exp_steps:
            exact_steps += 1
        if [s.get("phase") for s in pred_steps] == [s.get("phase") for s in exp_steps] and [s.get("operation") for s in pred_steps] == [s.get("operation") for s in exp_steps]:
            exact_sequences += 1
        total_expected_steps += len(exp_steps)
        total_pred_steps += len(pred_steps)
        for i in range(max(len(exp_steps), len(pred_steps))):
            if i < len(exp_steps) and i < len(pred_steps):
                matching_step_fields += sum(pred_steps[i].get(k) == exp_steps[i].get(k) for k in STEP_FIELDS)
    total_field_slots = max(total_expected_steps, total_pred_steps) * len(STEP_FIELDS)
    return {
        "cases": n,
        "case_status_accuracy": round(status_correct / n, 6) if n else 0,
        "exact_step_array_accuracy": round(exact_steps / n, 6) if n else 0,
        "sequence_accuracy": round(exact_sequences / n, 6) if n else 0,
        "step_field_accuracy": round(matching_step_fields / total_field_slots, 6) if total_field_slots else 0,
        "reference_steps": total_expected_steps,
        "predicted_steps": total_pred_steps,
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("dataset"))
    parser.add_argument("--sample-only", action="store_true")
    args = parser.parse_args()
    reference_path = args.dataset / "sample_output.csv"
    requests_path = args.dataset / "sample_deletion_requests.csv"
    if not reference_path.is_file() or not requests_path.is_file():
        print("evaluator: sample inputs and reference output are required", file=sys.stderr)
        return 2
    try:
        with tempfile.TemporaryDirectory() as td:
            # Run against the provided sample requests without replacing the production
            # dataset file or copying the evidence tree into a temporary directory.
            output = Path(td) / "sample_output.csv"
            engine = Path(__file__).with_name("main.py")
            subprocess.run([
                sys.executable, str(engine),
                "--dataset", str(args.dataset),
                "--requests", str(requests_path),
                "--output", str(output),
            ], check=True)
            metrics = score(read_rows(output), read_rows(reference_path))
            print(json.dumps(metrics, indent=2))
            if metrics["case_status_accuracy"] != 1 or metrics["exact_step_array_accuracy"] != 1:
                return 1
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"evaluator: error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
