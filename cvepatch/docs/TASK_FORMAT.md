# Defensive Task Format

A defensive task is defined by **two** validated manifests plus a source
baseline and an image. This document is the authoring reference.

## 1. The two manifests

| Manifest | Schema | Describes | Read by |
|----------|--------|-----------|---------|
| **Defensive task manifest** | `cvepatch/core/schemas/defensive_task.schema.json` | the vulnerability: CVE/commit, class, build + regression commands, expected results, provenance, evidence | the trusted grader (inside the image) |
| **Env manifest** | `cvepatch/contract/schemas/manifest.schema.json` | the image/env record: interface, image ref, `evaluate.command`, episode/evaluation tools | the runner |

They are deliberately separate: the env manifest is the runner's existing
contract (unchanged); the defensive task manifest carries task semantics the
runner never needs to understand.

## 2. Defensive task manifest fields

See the JSON Schema for the authoritative list. Highlights and rules:

- **Identity / provenance**: `task_id`, `cve_id?`, `chromium_issue_id?`,
  `product`, `component`, `vulnerability_class`, `cwe_ids`,
  `affected_versions`, `source_repository`, `vulnerable_commit`,
  `fixed_commit?`, `patch_commit?`.
  - Every `?` field is explicitly nullable. **Never invent** a CVE, fixing
    commit, or patch. A missing fact is `null`, not a guess.
- **`patch_provenance`**: `{status, source?, content_sha256?, retrieved_at?,
  note?}`. `status` ∈ `verified | claimed | unknown | absent`.
  `verified` **requires** a `content_sha256` — an advisory link alone is
  never proof (enforced by the loader).
- **`build_instructions`**: `{mode: dev|reproducible, command: [...],
  workdir?, timeout_s, toolchain?}`. `command` is argv run in the checkout.
- **`regression_test_command`**: `{command, workdir?, timeout_s, invariant}`
  or `null`. The trusted regression test encoding the security invariant.
  Convention: **exit 0 ⇔ invariant holds (safe)**; non-zero ⇔ violated.
  `null` ⇒ no reliable oracle ⇒ the verdict is capped at
  `INCONCLUSIVE`/`MANUAL_REVIEW`.
- **`existing_test_command`**: `{command, ...}` or `null`. The pre-existing
  functional suite. Catches patches that break behavior or merely suppress
  the regression test.
- **`security_checks`**: optional extra `{name, command, kind}` checks
  (sanitizer / static / property / regression). Cleanliness here is never
  sufficient on its own.
- **`validation_strategy`** ∈ `regression | regression_plus_existing |
  differential | manual_only`. Selects which trusted checks are **required**
  for `PATCH_VERIFIED`.
- **`patched_files_allowlist`**: relative source paths the candidate patch
  may touch. Empty = any path under the tree (still traversal-checked). Use
  it to stop "edit the test" cheats.
- **`expected_baseline_result`** ∈ `regression_fail | regression_pass |
  unknown`; **`expected_patched_result`** ∈ `regression_pass | unknown`.
- **`resource_limits`**: `{cpu, memory_mb, pids, wallclock_s}`. `pids` is
  enforced by the container cgroup (`--pids-limit`), not a host rlimit.
- **`network_policy`** ∈ `none | restricted`. Default `none`.
- **`task_status`**: the task-definition lifecycle status.
- **`evidence`**: ≥1 `{kind, source, retrieved_at, content_sha256?, note?}`.
- **`limitations`**: free-form caveats (e.g. "oracle is a canary, not a PoC").

### Cross-field rules (loader-enforced)
- A `regression*` / `differential` strategy requires a
  `regression_test_command`.
- `regression_plus_existing` also requires `existing_test_command`.
- `manual_only` must **not** declare a regression command.
- `expected_baseline_result: regression_fail` requires a regression command.
- `patch_provenance.verified` requires `content_sha256`.

## 3. Env manifest (defensive flavor)

```yaml
schema_version: "1"
env_id: <id>
interface: rl.mcp.vulnerability_defense.v1
interface_flavor: rl_mcp_v1            # cli_oneshot grading path
task_type: binary_patch
image: { ref: <image>, digest: null }
expected_capabilities: [ ... defensive dims ... ]
mcp:
  episode_tools: [setup, read_file, list_directory, search_code,
                  inspect_diff, run_static_analysis, run_tests,
                  apply_patch, submit_patch, submit_report]
  evaluation_tools: [grade_defensive]   # MUST be disjoint from episode_tools
evaluate:
  kind: cli_oneshot
  command: [python, -m, cvepatch.core.verifier.deterministic_grader,
            --run, /run, --task, /opt/defensive/task/defensive_task.json,
            --baseline, /opt/defensive/baseline]
  timeout_s: 300
metadata:
  defensive_task_manifest: task/defensive_task.json
```

The interface registry enforces: `episode_tools ⊆` the interface's declared
tools; `evaluation_tools` disjoint from `episode_tools`; `cli_oneshot`
interface ⇒ `evaluate.kind: cli_oneshot`.

## 4. The defensive result (grader output)

`validation_result.schema.json`. The grader emits one JSON object with:

- `final_status` ∈ `PATCH_VERIFIED | REPRODUCIBLE | BUILDABLE | FAILED |
  INCONCLUSIVE | MANUAL_REVIEW | UNSUPPORTED`.
- `dimensions`: each of the 12 defensive dimensions as `true|false|null`
  (`null` = unknown / not evaluated, **never** success).
- `capabilities`: the flat `{dim: bool}` projection the shared runner scores.
- `steps`: the A–G pipeline record. `failure_reasons`, `evidence`,
  `patch_sha256`, and an optional `report` block (kept separate from the
  verdict).

`PATCH_VERIFIED` is produced only when the strategy's required trusted checks
pass **and** provenance requirements are met. An LLM never contributes to it.

## 5. Worked example

See `testenvs/defensive-fixture/` for a complete, runnable example: a
synthetic off-by-one in a bounded string copy, with a deterministic
guard-byte regression oracle, a functional suite, a reference patch, both
manifests, the MCP server, and the in-image grader.
