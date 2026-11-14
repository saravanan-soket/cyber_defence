# Defensive Benchmark Runbook

How to create, run, and inspect a defensive vulnerability-defense task. Start
with the synthetic fixture (fast, no V8); scale to V8 last.

## 0. Prerequisites

- Python 3.11+ (`requires-python = ">=3.11"`). The runner/grader use
  `datetime.UTC` and `StrEnum`, which are 3.11+.
- A C compiler (`cc`/`gcc`) for the fixture.
- Docker **only** for the containerized end-to-end path. The unit + the host
  end-to-end tests run without Docker.

```bash
make install           # venv + deps + submodules + git hooks
# or, for a 3.11 env via uv (if system python is older):
uv venv --python 3.11 .venv && uv pip install -e ".[dev]"
```

## 1. Run the full test suite

```bash
make test                               # unit + golden (no Docker, no API)
.venv/bin/pytest -q cvepatch/tests/unit/test_defensive_*.py \
                    cvepatch/tests/integration/test_defensive_e2e.py
```

The defensive tests cover schema validation, identifier normalization, dedup,
provenance, patch parsing + path-traversal rejection, baseline reproduction,
build/regression failure, successful verification, missing-oracle handling,
timeouts, hidden-grader isolation, result-schema validation, catalog/DB
integration, and the offensive-workflow regression.

## 2. Run the fixture defensive task end-to-end (no Docker)

The host path exercises the exact grader + pipeline the container runs:

```bash
.venv/bin/python - <<'PY'
from pathlib import Path
from cvepatch.core.verifier import deterministic_grader as G
import json, tempfile
run = Path(tempfile.mkdtemp())
patch = Path("testenvs/defensive-fixture/reference/fix.patch").read_text()
(run/"tool_calls.jsonl").write_text(json.dumps(
    {"tool":"submit_patch","args":{"patch":patch},"result":"{}"})+"\n")
out = G.grade(run_dir=run,
              task_path=Path("testenvs/defensive-fixture/task/defensive_task.json"),
              baseline_dir=Path("testenvs/defensive-fixture/baseline"))
print(out["final_status"], json.dumps(out["capabilities"]))
PY
# -> PATCH_VERIFIED {...}
```

## 3. Run the fixture through the real runner (Docker)

```bash
# 3a. Build the fixture image (stages a minimal context; seconds).
bash testenvs/defensive-fixture/build.sh        # -> local/defensive-fixture:latest

# 3b. Register the env in the catalog (records manifest_path).
.venv/bin/cvepatch register-defensive testenvs/defensive-fixture/env_manifest.yaml

# 3c. (optional) Validate the image's tool surface vs. the manifest.
.venv/bin/cvepatch validate-image defensive-fixture-strbuf-01

# 3d. Drive the plumbing with the mock LLM (no API, no spend).
.venv/bin/cvepatch benchmark --config benchmarks/defensive-fixture.yaml --mock-llm

# 3e. Run with a real model.
.venv/bin/cvepatch benchmark --config benchmarks/defensive-fixture.yaml \
    --models anthropic/claude-opus-4-7
```

### Inspect result artifacts
```
runs/defensive-fixture/<host>/<ts>/<run_id>/
  score.json         # defensive bitmap (capabilities) + score + status
  grade_calls.jsonl  # the full validation_result emitted by the grader
  tool_calls.jsonl   # agent tool calls (carries the submitted patch)
  transcript.jsonl   # full chat transcript
  cost.json          # tokens + spend
```

`score.json.capabilities` is the defensive dimension bitmap (NOT the
offensive 16-flag set); `score.json.score` is the defensive weighted score.

## 4. Scale to V8

The V8 image is ~65–70 GB and needs the V8 build toolchain + a running Docker
daemon. The V8 defensive builder reuses `benchmarks/bench-v8/env-builder/`.

```bash
# 4a. Ingest + classify candidate CVEs (offline-first; cache-backed).
.venv/bin/python - <<'PY'
from pathlib import Path
from cvepatch.core.ingestion.store import CandidateStore
s = CandidateStore()
s.ingest_jsonl("path/to/candidates.jsonl")   # or ingest_cve / ingest_source_ref
Path("candidates.resolved.jsonl").write_text(s.to_jsonl())
PY

# 4b. Author + validate a defensive task manifest for one CVE.
.venv/bin/python -c "from cvepatch.core import manifest as m; \
    m.load('tasks/v8-cve-XXXX.json'); print('valid')"

# 4c. Build the V8 defensive image (operator step; reuses bench-v8 bootstrap).
git submodule update --init benchmarks/bench-v8
python benchmarks/bench-v8/env-builder/bootstrap_v8.py --bug <id> --crev <vuln_crev>
#   ...then layer the defensive baseline/task/grader into the image (see the
#   fixture Dockerfile for the layout the grader expects under /opt/defensive).

# 4d. Register + validate + run.
.venv/bin/cvepatch register-defensive tasks/v8-cve-XXXX.env.yaml
.venv/bin/cvepatch benchmark --config benchmarks/defensive-v8.yaml \
    --envs v8-defensive-cve-XXXX --seeds 1 --cost-cap-usd 50
```

Reproduction + patch verification still run through the trusted cli_oneshot
grader inside the image; a built image never auto-advances past `BUILDABLE`.

## 5. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `final_status: FAILED`, `infrastructure_failure: true` | build/test harness or grader crashed. Check `grade_calls.jsonl` steps + `output_excerpt`. Often an unbuildable baseline or a too-tight `resource_limits`. |
| `MANUAL_REVIEW` | no reliable oracle (`regression_test_command: null` / `manual_only`). Expected when a task has no mechanical invariant. |
| `INCONCLUSIVE` | baseline did **not** reproduce the defect under the oracle — the oracle is unreliable for this task; do not claim a fix. |
| Build fails with "fork: Resource temporarily unavailable" | a per-UID process cap. Do not set `RLIMIT_NPROC` on the host; use the container `--pids-limit`. |
| `cli_oneshot grader failed` in the runner | the grader exited non-zero or emitted non-JSON. Re-run its argv manually inside the image against a `/run` mount. |
| Patch rejected at step A | path traversal / absolute path / out-of-allowlist / empty. See `failure_reasons`. |

## 6. Limitations (current)

- Only the synthetic fixture ecosystem is wired end-to-end here. V8 is
  designed + documented; building its image is an operator step gated on
  hardware.
- The fixture oracle is a deterministic guard-byte canary, not a sanitizer or
  a real PoC. Real tasks should prefer an ASan/PoC-based regression where
  available (declare it via `security_checks`).
- No differential or static-analysis oracle is implemented yet (the `base`
  interfaces exist). Static-analysis cleanliness is never sufficient for a
  verdict by design.
- Multi-file / build-system patches are supported by the pipeline but not yet
  exercised by a shipped task.
