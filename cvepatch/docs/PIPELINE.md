# cvepatch pipeline

From a CVE record to a verified, labelled reasoning trace.

```
cve_triage.jsonl + advisories.jsonl
  │  scripts/taskgen.py            (host: clone + read diffs only, never runs code)
  ▼
task bundle  runs/defensive-tasks/<lang>/<task_id>/
  │  scripts/taskgen_confirm.py    (DinD Job: build image, verify the reference solution)
  ▼
REPRODUCIBLE task (registered env)
  │  cvepatch benchmark            (DinD Job: GLM-5.3 episode in the task image)
  ▼
run dir: transcript.jsonl, tool_calls.jsonl, tools.json
  │  verifier (fresh container, --network none, hidden/ mounted read-only)
  ▼
verdict (tier T1–T4 / rejected)  →  grade_calls.jsonl  +  Langfuse trace with scores
  │  scripts/export_traces.py --min-tier T2
  ▼
training JSONL (OpenAI chat format, reasoning_content kept)
```

## Keep-everything mode (worker.py --keep-all --run-all)

Every CVE becomes a task and gets a GLM patch trace; nothing is dropped for
being hard to grade. Each trace is labelled (Langfuse tags + metadata.labels,
also in the worker's per-task result) so a training set can be filtered later:

| Label | Meaning |
|---|---|
| `deps_changed:True` | the fix changes dependency manifests (setup has network; the patch episode does not) |
| `test_renamed:True` | the fix renames a test file |
| `ref:no_code_fix` / `ref:empty` | none of the CVE's fix commits changes code (version bump, CI, docs); the baseline may already be fixed |
| `env:agent_setup` | the language builder could not handle the layout; an agent set it up |
| `env:unbuilt` | setup failed; the episode ran on the bare toolchain image |
| `confirm:<status>` | REPRODUCIBLE / BUILDABLE / INCONCLUSIVE / SKIPPED |
| `setup:<status>`, `setup_model:<model>` | how the environment was made |
| `tier:<T1..T4/rejected>` | the verifier's grade (as before) |

Still skipped: root commits (no vulnerable version) and clone/git failures
(retried). Kernel and Android CVEs are out of scope (no container).

## Two kinds of bundle

| `--lang` | Commands come from | Image |
|---|---|---|
| go, python, javascript, java, rust, php, ruby | the language adapter (`languages.py`) | built from the bundle's Dockerfile |
| native (git-only projects, mostly C/C++), dotnet, elixir | an **agent setup episode** (`setup_adapters.py`) | committed from that episode |

Fix commits are taken from any git host: triage records `fix_refs` (repo + sha)
from CVE commit links (GitHub, GitLab, Bitbucket, googlesource, cgit/gitweb,
SourceForge, Gitea-style forges) and from OSV GIT ranges (`commit_ref.py`).

### Agent setup (setup-mode bundles)

The result of a setup is a **recipe** (`install_script` + `build_command` +
`test_command`, a few KB): the task image is built from it (base image + the
install script), so it survives the pod, rebuilds anywhere without an LLM, and
is tried first for other CVEs of the same repository (`runs/setup-recipes/`).
Setup episodes can use a different model from patch episodes
(`worker.py --setup-model openai/gpt-oss-120b --model openai/glm5.3-defense`).

Older notes on the committed-container fallback:

`scripts/agent_setup.py` (DinD Job `deploy/kube/cvepatch-setup.yaml`) runs
before confirmation, per bundle:

1. build the base image (toolchain + vulnerable source + MCP server);
2. setup episode with GLM: **network on, root**, `DEF_MODE=setup`. The agent
   installs what the project needs and calls `submit_setup(build_command,
   test_command)`, which re-runs both as `agent` on a fresh copy of the source;
3. `docker commit`, then reset: workspace wiped; `/rlenv/src`,
   `/opt/defensive`, `/opt/pkg`, `/opt/venv`, `/opt/vpy` restored from the base
   image; `USER agent`; commands in `/opt/defensive/task/setup.json` (shown to
   the patch agent by `setup()` as `environment`);
4. leak check (`leakcheck.py`): the fix's distinctive added lines in any file,
   or a `.git` holding the fix commit → `LEAKED`, image deleted;
5. commands written to `hidden/task.json` (build + existing tests) and, when
   the fix ships tests, `hidden/oracle/setup_cmd.sh` (the oracle = upstream
   tests overlaid + the whole suite).

Confirmation then reuses that image (no rebuild) and runs build + tests
**offline**; until setup succeeds a bundle confirms as `NEEDS_SETUP`. Setup
traces go to Langfuse as `cvepatch-setup:<CVE>`, tag `phase:setup`.

## Task bundle

| Path | In image? | Contents |
|---|---|---|
| `baseline/` | yes | source at the vulnerable commit (`git archive`, no history) |
| `public/defensive_task.json` | yes | redacted task: repo, vulnerable commit, language, advisory (CVE description, CWE, affected versions). No fix commit, no file names, no commands, no evidence URLs |
| `hidden/task.json` | no | full task: fix commit, build / oracle / existing-test commands, compile-failure pattern |
| `hidden/oracle/` | no | the fix commit's test files + `run.sh` that overlays and runs only them |
| `hidden/reference/fix.patch`, `test.patch` | no | the upstream fix, split into code and tests |

The agent has a shell in its container, so nothing under `hidden/` may enter
the image: it is excluded by `.dockerignore` and bind-mounted into the
verifier's container only (`evaluate.mounts` in `env_manifest.yaml`).
Dependency caches are warmed for the whole project, so the image does not
single out the fixed package or module either.

## Agent workflow (MCP tools in the task container)

`setup()` returns the advisory and the instructions:

1. **locate** the root cause (`read_file`, `list_directory`, `search_code`)
2. **reproduce**: write a regression test in the project's own framework that
   fails on the vulnerable code (`write_file`, `run_command`)
3. **patch** the source (`write_file` / `apply_patch`)
4. **verify**: the test passes, existing tests still pass (`run_command`)
5. **submit**: `submit_fix(test_files, test_command)` splits the workspace diff
   into the test and the fix; `submit_report(report)` records the root cause

No network in the episode. The upstream fix is never shown to the agent.

## Verifier tiers (`cvepatch/core/verifier/verify.py`)

Every check runs the command `--repeats` times (default 2) and requires the
same outcome each time.

| Check | Meaning |
|---|---|
| `agent_test_fails_on_vuln` | the agent's test fails on the vulnerable tree, and not because it fails to compile there |
| `agent_test_passes_on_fix` | it passes with the agent's fix (after the project builds) |
| `existing_tests_passed` | the project's other tests still pass |
| `upstream_test_fails_on_vuln` / `upstream_test_passes_on_fix` | the upstream fix's own tests, against the vulnerable tree / the agent's fix |
| `agent_test_passes_on_upstream_fix` | the agent's test also passes on the upstream fix, so it tests the bug, not the agent's particular patch |
| `agent_test_passes_on_fixed_release` | same against `hidden/fixed_release/` (CVEs with a fixed version but no commit) |

**base** = fix and test apply, build ok, fails on vuln, passes on fix,
existing tests not failing.

| Tier | Requirement | When available |
|---|---|---|
| T1 | base + upstream tests fail on vuln and pass on the agent's fix | fix commit with tests |
| T2 | base + agent's test passes on the upstream fix | fix commit |
| T3 | base + agent's test passes on a fixed release | fixed version known |
| T4 | base only (self-consistent) | always |
| rejected | anything less | |

Confirmation runs the same verifier on the reference solution (upstream fix +
upstream tests); a task is REPRODUCIBLE only if that is T1.

## Langfuse

After verification the runner posts the episode itself from the local
transcript (`cvepatch/runner/langfuse_sync.py`), because the proxy's callback
logs each call as a separate untagged trace and drops `reasoning_content`:

- trace `cvepatch:<CVE>`, session = CVE id, tags `tier:`, `cve:`, `lang:`, `env:`
- one generation per model turn: `output = {content, reasoning_content, tool_calls}`
- one span per tool call (args in, result out, truncated at 20k chars)
- scores: `tier` (categorical), `tier_rank` (T1=4 … rejected=0), one boolean per check

Prior reasoning is replayed to self-hosted GLM on every turn
(`runner/llm/messages.py`), so the recorded chain is the one the model saw.

## Commands

```bash
# once: advisory text for every open-source CVE
python scripts/extract_advisories.py --cve-zip <cvelist.zip.zip> \
    --rows <cve_triage.jsonl> --out <advisories.jsonl>
# host split (any languages)
python scripts/taskgen.py --rows <cve_triage.jsonl> --lang go,python,javascript,java,rust,php,ruby \
    --n 20 --cache <git cache> --out runs/defensive-tasks
# setup-mode languages: agent setup + confirm (DinD Job, LLM + Langfuse)
python scripts/taskgen.py --rows <cve_triage.jsonl> --lang native,dotnet,elixir --n 20 \
    --cache <git cache> --out runs/defensive-tasks
kubectl -n cvepatch create -f deploy/kube/cvepatch-setup.yaml
# confirm (DinD Job, created by the operator)
kubectl -n cvepatch create -f deploy/kube/cvepatch-taskgen.yaml
# run GLM-5.3 on confirmed tasks
python scripts/make_run_config.py --tasks runs/defensive-tasks --out benchmarks/cvepatch-glm53.yaml
kubectl create -f deploy/kube/cvepatch-run.yaml        # with BENCH_CONFIG set
# training data
python scripts/export_traces.py --runs runs/defensive --out traces.jsonl --min-tier T2
```
