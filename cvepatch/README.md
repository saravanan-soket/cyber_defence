# cvepatch

Find, patch and regression-test known vulnerabilities (CVEs) with an LLM
agent, verify every result with executable tests, and keep the full
reasoning trace of each attempt for training.

For each CVE the agent works inside a sandboxed container holding the
vulnerable source:

```
CVE record → vulnerable source in a container
  setup      get the project building and its tests running
  locate     read the CVE text + code, find the root cause
  reproduce  write a regression test that FAILS on the vulnerable code
  patch      write a minimal fix
  verify     regression test passes, existing tests still pass
  submit     patch + test + root-cause report
→ independent verifier (offline, fresh container) → quality label
```

The upstream fix commit, when one exists, is never shown to the agent; the
verifier uses it to check the agent's work. Every model call (including the
model's reasoning) is traced to Langfuse with the CVE, the verdict and the
quality tier attached, and also written to the run's local `transcript.jsonl`.

## Layout

```
cvepatch/
  core/          everything that runs inside a task container, self-contained
    ingestion/   CVE / advisory / fix-commit resolution, lifecycle states
    taskgen/     CVE + fix commit → task bundle (Go, Python, JS/TS, Java,
                 Rust, PHP, Ruby adapters)
    mcp_server/  tools the agent gets inside the container
    validation/  build + regression + existing-test pipeline
    verifier/    post-episode deterministic verifier (no LLM judge)
    env_builder/ fixture + V8 environment builders
  runner/        agent loop, LLM clients (LiteLLM → GLM-5.3), MCP client,
                 transcripts, budgets, resume
  contract/      env-manifest schema + interface registry
  cli.py         `cvepatch` command
scripts/         triage, extract_advisories, taskgen, taskgen_confirm,
                 make_run_config, export_traces
deploy/          LiteLLM proxy config + k8s Jobs (DinD pods)
testenvs/        cvepatch-fixture (new flow), defensive-fixture, defensive-v8
docs/            PIPELINE (start here), ARCHITECTURE, RUNBOOK, TASK_FORMAT, CORE
```

## Quick start

```bash
make install
source .venv/bin/activate
cvepatch doctor
make smoke          # fixture env + one mock-LLM episode, no API spend
```

Task generation and confirmation build and test third-party repositories,
so they only run inside the k8s DinD Jobs in `deploy/kube/`; see
`docs/RUNBOOK.md`.

## Origin

Derived from ExploitBench (MIT, see `LICENSE`); the offensive benchmark code
has been removed.
