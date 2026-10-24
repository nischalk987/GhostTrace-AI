# GhostTrace AI

> **Deleted doesn't mean gone.**

GhostTrace AI is a hackathon project concept for evidence-first auditing of data-deletion requests. It is designed to identify residual personal data, reconstruct what the evidence shows at a specified audit time, surface restore/synchronization risks, and produce a machine-valid audit result with traceable evidence.

> **Project status:** Planning / implementation in progress. Features described below are planned until implemented and covered by tests.

## Goals

- **Evidence first:** Every factual finding must be traceable to a real evidence source.
- **Time aware:** Reconstruct state at `audit_at`; do not use later evidence to justify an earlier conclusion.
- **Policy aware:** Apply the provided deletion, retention, and legal-hold rules.
- **Deterministic core:** Use explicit rules and validators for final status and output formatting. An optional LLM may help parse ambiguous evidence, but must not invent facts or override policy checks.
- **Submission safe:** Validate the exact challenge output contract and keep evaluation artifacts reproducible.

## Planned architecture

```text
Challenge dataset
      |
      v
Input/schema validation
      |
      v
Request classification --> Identity resolution
      |                         |
      +------------+------------+
                   v
        Manifest-backed evidence index
                   |
                   v
       State reconstruction at audit_at
                   |
                   v
       Retention / deletion policy engine
                   |
                   v
       Findings + remediation + verification
                   |
                   v
       Output validator --> output.csv
                   |
                   v
       Evaluation reports + submission bundle

Optional UI:
React + Vite --> FastAPI --> audit engine
```

## Planned stack

- **Audit engine:** Python
- **API:** FastAPI
- **Frontend:** React + Vite
- **Data formats:** CSV, JSON, and SQLite where supported by the challenge evidence
- **Testing:** pytest plus deterministic schema/regression checks

The core audit engine and challenge output correctness take priority over optional UI/AI enhancements.

## Challenge output contract

The challenge requires the generated `output.csv` to have exactly these columns:

```csv
case_id,deletion_status,steps_json
```

Allowed statuses:

- `COMPLETE`
- `INCOMPLETE`
- `NOT_APPLICABLE`

Each step in `steps_json` must use the challenge-required schema and allowed operation/state combinations. The implementation must validate the full contract against the official challenge instructions before submission. Do not treat a reported status as evidence, and do not claim a future remediation has already happened.

## Development roadmap

Track work through [GitHub Issues](https://github.com/nischalk987/GhostTrace-AI/issues). The P0 issues cover the correctness-critical audit pipeline and submission validation. P1 covers API, user interface, evaluation, and safe reproducibility. P2 covers optional risk scoring and report enhancements.

Suggested order:

1. Identity resolution and evidence indexing.
2. Historical state reconstruction at `audit_at`.
3. Policy evaluation and risk detection.
4. Step generation and strict output validation.
5. Sample tests and full-dataset evaluation.
6. FastAPI integration and dashboard.
7. Optional explainability, risk scoring, and reports.

## Quality checks

Before considering a run ready:

- [ ] Input schema and required files are validated.
- [ ] Every request has exactly one output row.
- [ ] Output columns and status values are exact.
- [ ] `steps_json` is valid JSON and satisfies the step schema.
- [ ] Step numbers are consecutive and phases are correctly ordered.
- [ ] Operation/state pairs are allowed by the challenge.
- [ ] Evidence IDs are real and traceable to inspected evidence.
- [ ] Evidence after `audit_at` is excluded from historical conclusions.
- [ ] Sample fixtures and participant-created edge cases pass.
- [ ] Evaluation and model-usage reports reflect actual runs.
- [ ] Packaging excludes the dataset corpus, secrets, and local build environments.

## Local development

Setup/run instructions will be added with the first working implementation. Do not assume the project is runnable until the corresponding implementation and tests are committed.

## Responsible use and privacy

Use only the challenge-provided dataset and authorized test data. Avoid committing secrets or unnecessary personal information. Do not fabricate evidence, model usage, test results, or transcript/runtime details; report unknown metrics as unavailable rather than guessing.

## Project links

- [Repository](https://github.com/nischalk987/GhostTrace-AI)
- [Open issues and roadmap](https://github.com/nischalk987/GhostTrace-AI/issues)
