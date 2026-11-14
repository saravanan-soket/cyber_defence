# Defensive Vulnerability-Defense Benchmark — Architecture

> Status: living document. Phase 1 (repository analysis) + the minimal
> end-to-end defensive task are implemented and tested on a synthetic
> fixture. V8 integration interfaces are designed and documented; the
> real V8 image build is gated on hardware/Docker availability (see
> §9 "Migration strategy").

This document describes how CVEPatch is extended with a **defensive**
task type — where an agent investigates a known vulnerability, roots out
its cause, submits a patch, and a *trusted* pipeline independently verifies
the fix — while keeping the existing **offensive** exploit benchmark fully
operational.

---

## 1. The existing (offensive) architecture

CVEPatch evaluates whether an LLM agent can exploit a known software
vulnerability. The pieces that matter for this work:

### 1.1 Contract layer — `cvepatch/contract/`

- **`interfaces.py`** — an *interface registry*. Each interface
  (`rl.mcp.<task>.<version>`) declares the MCP tool surface an env must
  expose, the capability-flag bitmap its grader emits, the submission
  kind, and — critically — the **grader kind**:
  - `mcp_tool`: grading happens *during* the episode via an in-container
    `grade` tool (the legacy V8 path).
  - `cli_oneshot`: grading happens *after* the episode in a fresh
    container; the grader binary is **never exposed to the agent** during
    the episode. This is the reward-hacking guard.
- **`manifest.py` + `schemas/manifest.schema.json`** — the per-env
  manifest contract. Validated with JSON Schema (draft 2020-12) and
  cross-checked against the interface registry: episode tools ⊆ the
  interface's declared tools; `evaluation_tools` must be **disjoint** from
  `episode_tools`; `cli_oneshot` interfaces must grade via `cli_oneshot`.

### 1.2 Runner — `cvepatch/runner/`

- **`orchestrator.py`** — drives each `(model, env, seed)` tuple: resolves
  the image, marks the DB row running, builds the LLM client, opens an MCP
  session, runs the episode, then grades. For `cli_oneshot` envs it runs
  `run_cli_oneshot_grader(...)` after the episode and records the result.
- **`loop.py:run_episode`** — the agent loop. Enumerates MCP tools
  (filtering out `evaluation_tools`), converts them to the provider tool
  schema, and iterates llm.complete → tool calls → results until budget
  exhaustion / voluntary stop / `ace`.
- **`mcp_client.py`** — spawns `docker run --init --network none -i --rm
  <image_digest>` and speaks MCP stdio. `--network none` blocks
  exfiltration.
- **`cli_oneshot_grader.py`** — spawns `docker run --rm --network none
  --volume <run_dir>:/run:ro <image> <argv…>`, parses the grader's JSON
  stdout (`{capabilities: {flag: bool}, …}`), and returns a `GradeResult`.
  Enforces a timeout and a flag-shaped-ref guard (`assert_safe_image_ref`).
- **`capabilities.py`** — `compute_score(capabilities, policy)`. Default
  offensive policy is `capability_uniform_sum_v1_ace_max`.
- **`run_dir.py`** — on-disk artifacts: `job.json`, `score.json`,
  `cost.json`, `grade_calls.jsonl`.

### 1.3 Catalog + DB — `cvepatch/catalog.py`, `cvepatch/db/schema.py`

- `rlenv_images` catalogs registered envs. The orchestrator calls
  `load_env_manifest(env_id)` (via `runner/env_manifest.py`), which reads
  `metadata.manifest_path` off the catalog row; a declared-but-broken
  manifest **fails closed** (infra_failed) rather than silently downgrading
  the grading contract.
- `runs` holds one row per episode. Schema migrations are idempotent
  `CREATE TABLE IF NOT EXISTS` + `ADD COLUMN` (schema v7 today).

### 1.4 Env image shape — `testenvs/sample-stack-bof/`

The simplest reference env: a Dockerfile that compiles a vulnerable binary,
a Python MCP server (`setup / exec / list_directory / read_file /
write_file / grade`), and a `problem/` dir with the prompt. The server runs
as an unprivileged `agent` user. This is the template the defensive fixture
env follows.

### 1.5 bench-v8 submodule — `benchmarks/bench-v8/`

The real V8 env factory. `env-builder/bootstrap_v8.py` generates a
standalone Dockerfile per bug from V8 source at a pinned commit, with
build configs (`args.*.gn`), the patch, and a Go MCP server. The V8 image
is ~65–70 GB and requires a full V8 build toolchain. **We reuse this
builder for the V8 defensive task (see §8); we do not replace it.**

---

## 2. Design principles for the defensive extension

1. **Shared runner, separate task semantics.** The defensive task is a new
   `cli_oneshot` interface driven by the *existing* orchestrator, loop, MCP
   client, DB, transcript recorder, cost tracker, and resume logic. No
   second runner, DB, MCP client, or LLM layer.
2. **The trusted verdict is executable, not model-judged.** The final
   verdict comes only from the deterministic validation pipeline (build +
   regression tests + explicit rules). An LLM never decides whether a patch
   is correct.
3. **A build is not a fix.** Image build success, container start, and
   static-analysis cleanliness never advance a task toward
   `PATCH_VERIFIED`.
4. **Provenance is first-class.** Every ingested fact and every lifecycle
   transition carries a source reference, timestamp, and content hash.
   Missing CVE / fix-commit / regression test is represented explicitly;
   nothing is invented or silently substituted.
5. **Backward compatibility is non-negotiable.** Offensive interfaces,
   scoring, manifest schema, and DB columns keep their exact meaning.

---

## 3. Where the new code lives

The defensive package sits **inside** the installed `cvepatch` package
(not a top-level `defensive/`) so it is importable, shares the contract /
runner modules, and its tests are collected by the existing pytest config
(`testpaths = ["cvepatch/tests"]`). The prompt's proposed `defensive/`
tree is mapped onto the repo as follows:

```
cvepatch/core/
  schemas/                       # JSON Schemas (strict validation)
    defensive_task.schema.json
    patch_submission.schema.json
    validation_result.schema.json
  manifest.py                    # DefensiveTask manifest loader/validator
  report.py                      # root-cause report schema + mechanical checks
  ingestion/
    identifiers.py               # normalize CVE / crbug / GHSA ids
    provenance.py                # EvidenceRef: source, retrieved_at, sha256
    lifecycle.py                 # status enum + documented transition table
    cve_client.py                # pluggable metadata source (offline cache-first)
    chromium_issue_client.py     # Chrome-vs-V8 attribution
    advisory_resolver.py         # advisory -> candidate commits (evidence only)
    patch_resolver.py            # fixing-commit resolution (never auto-trusted)
    store.py                     # JSON/JSONL manifest ingestion + dedup
  env_builder/
    base.py                      # EnvironmentBuilder ABC (11 lifecycle methods)
    fixture_builder.py           # builds the synthetic fixture (real, fast)
    v8_builder.py                # reuses bench-v8 env-builder (documented)
    manifest.py                  # reproducibility manifest emitter
  oracle/
    base.py                      # RegressionOracle ABC
    regression_oracle.py         # command-exit-code / invariant oracle
  validation/
    patch_validator.py           # unified-diff parse, path-traversal reject, apply
    pipeline.py                  # the trusted A–G pipeline (pure Python)
  grader/
    deterministic_grader.py      # cli_oneshot entrypoint (host lib + in-image CLI)
    metrics.py                   # defensive score schema + scorer
  mcp_server/
    tools.py                     # defensive MCP tool implementations

cvepatch/contract/
  interfaces.py                  # + rl.mcp.vulnerability_defense.v1
  manifest.py                    # task_type 'binary_patch' already allowed

cvepatch/runner/
  scoring.py                     # NEW: interface-aware scorer dispatch
  orchestrator.py                # one-line change: score via dispatcher

testenvs/defensive-fixture/      # synthetic, non-dangerous defect + MCP server + grader
benchmarks/defensive-v8.yaml     # defensive benchmark config
cvepatch/tests/unit/test_defensive_*.py
cvepatch/tests/integration/test_defensive_e2e.py
docs/ARCHITECTURE.md / DEFENSIVE_TASK_FORMAT.md / DEFENSIVE_RUNBOOK.md
```

---

## 4. The defensive task contract

### 4.1 Interface

`rl.mcp.vulnerability_defense.v1`:
- base `rl.mcp.base.v1`
- `task_type: binary_patch` (already a valid manifest enum)
- grader kind `cli_oneshot` (grader never in the episode tool surface)
- episode tools: `setup, read_file, list_directory, search_code,
  inspect_diff, run_static_analysis, run_tests, apply_patch, submit_patch,
  submit_report`
- evaluation tools: `grade_defensive` (reserved; filtered from the agent)
- capability flags = the **defensive dimensions** (§7), *not* the offensive
  16-flag bitmap.

### 4.2 Task manifest

`defensive_task.schema.json` — one validated JSON manifest per task, with
the fields enumerated in the task spec (`schema_version`, `task_id`,
`task_type`, `cve_id?`, `chromium_issue_id?`, `product`, `component`,
`vulnerability_class`, `cwe_ids`, `affected_versions`, `vulnerable_commit`,
`fixed_commit?`, `source_repository`, `patch_commit?`, `patch_provenance`,
`build_instructions`, `regression_test_command`, `validation_strategy`,
`expected_baseline_result`, `expected_patched_result`, `resource_limits`,
`network_policy`, `task_status`, `evidence`, `limitations`). Missing
optional authoritative facts (CVE, fix commit, patch) are **explicitly
nullable** and never fabricated.

This defensive manifest is the *task* definition. It is distinct from the
runner's per-env `manifest.schema.json` (the *env/image* record). A
defensive task ships both: the env manifest wires it into the runner
(`interface`, `image`, `evaluate.command`, `evaluation_tools`), and the
defensive task manifest carries the vulnerability semantics and expected
results that the grader reads.

---

## 5. Data flow (one defensive episode)

```
                        host (trusted)                         container (untrusted agent)
 ┌───────────────────────────────────────────┐       ┌───────────────────────────────────────┐
 │ orchestrator.run_one_tuple                 │       │ defensive MCP server (as `agent`)       │
 │  1. resolve image digest                   │       │   setup(): task description + submit    │
 │  2. mark DB row running                    │       │           format (NO hidden patch,      │
 │  3. McpDockerSession.start(--network none) │──────▶│           NO oracle, NO grader)         │
 │  4. run_episode(loop):                     │ stdio │   read_file / list_directory /          │
 │       enumerate tools, FILTER OUT          │◀─────▶│   search_code  → /rlenv/src (read-only) │
 │       evaluation_tools (grade_defensive)   │       │   apply_patch / submit_patch            │
 │       llm ↔ tool calls …                   │       │           → /rlenv/workspace (writable) │
 │       submit_patch writes candidate.patch  │       │   submit_report → report.json           │
 │  5. episode ends                           │       └───────────────────────────────────────┘
 │  6. run_cli_oneshot_grader:                │
 │       docker run --rm --network none       │       ┌───────────────────────────────────────┐
 │         -v run_dir:/run:ro <image>         │──────▶│ fresh container, deterministic_grader   │
 │         <grade argv>                       │       │   reads /run/…/candidate.patch          │
 │       parse JSON {capabilities,…}          │◀──────│   runs trusted A–G pipeline:            │
 │  7. score via scoring.py dispatcher        │ stdout│    A validate submission                │
 │       (defensive policy, NOT offensive sum)│       │    B baseline reproduction              │
 │  8. write score.json / grade_calls.jsonl   │       │    C candidate build                    │
 │       update runs row                      │       │    D regression verification            │
 └───────────────────────────────────────────┘       │    E existing test suite                │
                                                      │    F independent security checks        │
                                                      │    G deterministic verdict → JSON       │
                                                      └───────────────────────────────────────┘
```

The grader reads the submitted patch from the read-only `/run` mount and
operates on a **trusted copy** of the source baked into the image under a
root-owned path (`/opt/defensive/`), which the agent cannot modify. The
agent's workspace is a separate writable mount.

---

## 6. The trusted validation pipeline (steps A–G)

Implemented as pure Python in `validation/pipeline.py`, so it runs both
on the host (fast unit/integration tests, no Docker) and inside the
container as the `cli_oneshot` grader.

| Step | Name | Produces | Fail semantics |
|------|------|----------|----------------|
| A | Validate submission | `patch_format_valid` | reject path traversal / out-of-tree / empty-when-required |
| B | Baseline reproduction | `baseline_reproduced` | if the vulnerable baseline does **not** exhibit the expected failure → `INCONCLUSIVE` / `MANUAL_REVIEW`, never "fixed" |
| C | Candidate build | `candidate_build_passed` | build failure ≠ fix |
| D | Regression verification | `regression_test_passed` | candidate must satisfy the security invariant |
| E | Existing test suite | `existing_tests_passed` | catches patches that break functionality or merely suppress the regression test |
| F | Independent security checks | `security_checks_passed` | extra regression/sanitizer/static checks; cleanliness alone ≠ fixed |
| G | Final verdict | the full `validation_result.json` | `PATCH_VERIFIED` only when required trusted checks pass **and** provenance requirements are met |

No LLM judge participates in the verdict.

---

## 7. Defensive grading (separate from the offensive bitmap)

`grader/metrics.py` defines the versioned defensive score schema. Each
dimension is `true` / `false` / `null` (null = unknown/not-evaluated, **not**
success):

`detection_correct`, `root_cause_supported`, `patch_format_valid`,
`candidate_build_passed`, `baseline_reproduced`, `regression_test_passed`,
`existing_tests_passed`, `security_checks_passed`, `patch_provenance_verified`,
`validation_reproducible`, `false_positive`, `infrastructure_failure`.

The overall status is one lifecycle value (§ ingestion statuses). Component
results are always reported alongside — never collapsed into one opaque
number. Scoring is selected by interface through
`runner/scoring.py:score_for_interface`, which returns the existing
offensive sum for offensive interfaces (unchanged) and the defensive score
for `rl.mcp.vulnerability_defense.v1`.

---

## 8. Lifecycle statuses (ingestion + validation)

```
DISCOVERED → CLASSIFIED → BUILDABLE → REPRODUCIBLE → PATCH_VERIFIED
     │           │            │            │
     └───────────┴────────────┴────────────┴──▶ UNSUPPORTED | FAILED |
                                                 INCONCLUSIVE | MANUAL_REVIEW
```

- A successful image build advances at most to `BUILDABLE`, never to
  `REPRODUCIBLE` or `PATCH_VERIFIED`.
- `REPRODUCIBLE` requires step B to confirm the baseline exhibits the
  defect under the trusted oracle.
- `PATCH_VERIFIED` requires B (baseline reproduced) **and** C+D+E (+F where
  the task demands it) **and** provenance satisfied.
- Every transition stores a `reason` and `evidence` (see
  `ingestion/lifecycle.py`). Transitions not in the table raise.

---

## 9. Security boundaries

Reuses and does not weaken the offensive sandbox:

- Agent container runs `--network none`, as a non-root `agent` user.
- Source baseline mounted/placed read-only; a separate writable workspace
  holds the patch.
- The trusted grader, hidden reference patch, oracle, and expected results
  live under a **root-owned** path the agent cannot read or modify, and the
  grader runs in a *fresh* post-episode container — the agent never sees it.
- `grade_defensive` is an `evaluation_tool`, filtered out of the agent's
  tool surface by the loop (verified against the manifest's disjointness
  rule).
- `apply_patch` / `submit_patch` validate every path: unified-diff targets
  must be relative, inside the permitted source subtree, with no `..`
  components and no symlink escapes.
- No host Docker socket is mounted into the agent container. Resource,
  memory, CPU, pid, and timeout limits apply to builds/tests.
- Validation credentials and secrets are kept out of the agent container,
  prompts, and logs.

---

## 10. Migration strategy

- **DB:** no column meaning changes. Defensive runs populate the existing
  `runs` columns; `task_type='binary_patch'`, `interface=
  'rl.mcp.vulnerability_defense.v1'`. The per-dimension defensive verdict is
  serialized into `capabilities` (JSON) and `score.json`, mirroring how the
  offensive bitmap is stored, plus a `validation_result.json` artifact. No
  schema bump is required; if future columns are wanted they go through the
  existing idempotent `LATE_COLUMNS` path.
- **Scoring:** offensive `compute_score` is untouched; the orchestrator
  calls `score_for_interface`, which delegates to it for offensive
  interfaces.
- **V8:** the `v8_builder.py` reuses `bench-v8/env-builder/bootstrap_v8.py`
  to produce a defensive V8 image (baseline source at `vulnerable_commit`,
  fixing commit recorded). Because that image is ~65–70 GB and needs the V8
  build toolchain + a running Docker daemon, the end-to-end implementation
  and tests here use the **synthetic fixture** env
  (`testenvs/defensive-fixture/`), which builds in seconds and exercises
  every pipeline step and negative case. The V8 path is wired and
  documented; running it is an operator step on suitable hardware (see
  `docs/RUNBOOK.md`).

---

## 11. Components reused vs. new

**Reused unchanged:** `runner/orchestrator.py` loop/driver, `runner/loop.py`,
`runner/mcp_client.py`, `runner/cli_oneshot_grader.py`, `runner/budget.py`,
`runner/transcript.py`, `runner/cost.py`, `runner/resume.py`,
`runner/run_dir.py`, `db/schema.py`, `catalog.py`, `contract/manifest.py`
loader + env schema, the LLM client layer, and the CLI `benchmark` command.

**New:** the `cvepatch/core/` package, the defensive interface
entry in `contract/interfaces.py`, `runner/scoring.py` (+ a one-line
orchestrator change), the fixture env, `benchmarks/defensive-v8.yaml`, docs,
and tests.

**Minimal edits to shared code:** (1) register the new interface; (2)
replace the single hardcoded `compute_score(...)` call in the orchestrator
with the interface-aware dispatcher (offensive behavior preserved).
