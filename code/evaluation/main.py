"""Run the deterministic engine against the public 32-case sample reference."""
from __future__ import annotations
import argparse, csv, json, sys, tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "code"))
from main import generate, validate_output, InputError  # noqa: E402

def read_rows(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            raise InputError(f"Invalid CSV header in {path}: {reader.fieldnames!r}")
        return list(reader)

def parse_steps(row):
    return json.loads(row["steps_json"])

def compare(dataset: Path) -> dict:
    request_file = dataset / "sample_deletion_requests.csv"
    expected = read_rows(dataset / "sample_output.csv")
    with tempfile.TemporaryDirectory(prefix="ghosttrace-eval-") as temp:
        predicted_path = Path(temp) / "predicted.csv"
        generate(dataset, predicted_path, request_file)
        predicted = read_rows(predicted_path)
    validate_output(predicted, {r["case_id"] for r in expected})
    predicted_by_id = {r["case_id"]: r for r in predicted}
    expected_by_id = {r["case_id"]: r for r in expected}
    shared = sorted(set(predicted_by_id) & set(expected_by_id))
    status_correct = sum(predicted_by_id[k]["deletion_status"] == expected_by_id[k]["deletion_status"] for k in shared)
    row_exact = sum(
        predicted_by_id[k]["deletion_status"] == expected_by_id[k]["deletion_status"]
        and parse_steps(predicted_by_id[k]) == parse_steps(expected_by_id[k]) for k in shared
    )
    expected_step_tuples, predicted_step_tuples = [], []
    exact_sequences = 0
    for key in shared:
        expected_steps = parse_steps(expected_by_id[key])
        predicted_steps = parse_steps(predicted_by_id[key])
        if expected_steps == predicted_steps:
            exact_sequences += 1
        for step in expected_steps:
            expected_step_tuples.append(tuple(step.get(field) for field in
                ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")))
        for step in predicted_steps:
            predicted_step_tuples.append(tuple(step.get(field) for field in
                ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")))
    expected_counts, predicted_counts = Counter(expected_step_tuples), Counter(predicted_step_tuples)
    matched_steps = sum((expected_counts & predicted_counts).values())
    return {
        "sample_cases": len(shared),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(shared) if shared else 0.0,
        "exact_case_outputs": row_exact,
        "exact_case_output_accuracy": row_exact / len(shared) if shared else 0.0,
        "exact_step_sequence_cases": exact_sequences,
        "expected_step_count": len(expected_step_tuples),
        "predicted_step_count": len(predicted_step_tuples),
        "matched_step_tuples": matched_steps,
        "step_tuple_precision": matched_steps / len(predicted_step_tuples) if predicted_step_tuples else 1.0,
        "step_tuple_recall": matched_steps / len(expected_step_tuples) if expected_step_tuples else 1.0,
        "note": "Measured against the public sample_output.csv, not hidden-set accuracy."
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "dataset")
    args = parser.parse_args()
    try:
        print(json.dumps(compare(args.dataset), ensure_ascii=False, indent=2))
    except (InputError, OSError, ValueError, KeyError) as exc:
        print(f"evaluation error: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
