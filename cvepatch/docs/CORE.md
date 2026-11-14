# cvepatch.core

A defensive vulnerability-detection + patch-verification task family layered
on CVEPatch's shared runner. The agent investigates a known vulnerability,
roots out its cause, and submits a patch; a **trusted, executable** pipeline
independently builds the candidate and runs regression + existing tests to
produce a deterministic verdict. No LLM judges correctness.

See the docs for the full picture:
- [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md) — design, data flow, security boundaries.
- [docs/TASK_FORMAT.md](../../docs/TASK_FORMAT.md) — the two manifests + result schema.
- [docs/RUNBOOK.md](../../docs/RUNBOOK.md) — create / run / inspect / troubleshoot.

## Layout

```
schemas/        defensive_task / patch_submission / validation_result / root_cause_report (JSON Schema)
manifest.py     DefensiveTask loader + validation + cross-field rules
report.py       root-cause report schema + mechanical cross-checks
ingestion/      identifiers, provenance, lifecycle state machine, CVE/Chromium clients, candidate store
env_builder/    EnvironmentBuilder ABC + fixture builder (executable) + V8 builder (reuses bench-v8)
oracle/         Oracle ABC + sandboxed command runner + regression oracle
validation/     patch_validator (parse/traversal/apply) + pipeline (the trusted A-G steps)
grader/         metrics (defensive score) + deterministic_grader (cli_oneshot entrypoint)
mcp_server/     DefensiveToolbox + FastMCP wiring (runs inside the task container)
```

## Invariants

1. The final verdict comes only from executable tests + versioned rules.
2. A build succeeding never advances a task to REPRODUCIBLE / PATCH_VERIFIED.
3. Missing CVE / fix-commit / patch is represented explicitly; never invented.
4. The agent never sees the hidden reference patch, oracle, or grader.
5. Offensive scoring, the manifest schema, and DB column meanings are unchanged.

## Interface

`rl.mcp.vulnerability_defense.v1` (in `cvepatch.contract.interfaces`):
`cli_oneshot` grading, `task_type=binary_patch`, defensive capability flags
disjoint from the offensive 16-flag bitmap, scored by
`runner/scoring.py:score_for_interface`.
