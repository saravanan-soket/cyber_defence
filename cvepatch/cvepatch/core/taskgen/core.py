"""Language-neutral CVE -> defensive task builder.

One pipeline for every language. A per-language `Adapter` (languages.py)
answers four questions: which files are tests, how to run only the fix's
tests, how to fetch dependencies at image-build time, and which base image to
use. Everything else is shared here.

Host-side only: clones, reads diffs and writes files. Repository code is never
executed on the host; it runs only inside the task image (see
scripts/taskgen_confirm.py).

Bundle layout (`<out>/<task_id>/`):
    baseline/                 source at the vulnerable commit (no .git)    -> image
    public/defensive_task.json  redacted task the agent may see           -> image
    hidden/task.json          full task (fix commit, build/test commands)
    hidden/oracle/files/      the fix commit's test files
    hidden/oracle/run.sh      overlays them and runs only those tests
    hidden/reference/fix.patch, test.patch   upstream fix split into code / tests
    env_manifest.yaml, Dockerfile, .dockerignore, meta.json

Nothing under hidden/ is ever copied into the image: the agent has a shell in
its container. hidden/ is bind-mounted read-only into the verifier's
container only (env_manifest `evaluate.mounts`).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cvepatch.core.ingestion.advisory import scrub_advisory
from cvepatch.core.ingestion.provenance import sha256_text
from cvepatch.core.taskgen.commit_ref import CommitRef, parse_commit_url, repo_slug

MAX_SIBLINGS = 30


class SkipCandidate(Exception):
    """This CVE can't become a task; the message is the recorded reason."""


class NoCodeFix(SkipCandidate):
    """The fix commit changes no source code (a version bump, CI, docs...). With
    keep_all the caller tries the CVE's other fix commits before keeping it."""


@dataclass
class Change:
    status: str   # git name-status letter (A/M/D/R...)
    path: str     # new path
    old: str      # old path (== path unless renamed)


@dataclass
class Plan:
    """What an adapter decides for one task (after `detect`)."""

    image: str
    oracle: str                       # shell snippet, run from the checkout root
    compile_fail_re: str              # output pattern meaning "tests didn't compile/load"
    build: list[str]                  # argv
    existing: list[str] | None        # argv for the project's other tests, or None
    agent_tests: dict[str, list[str]]  # selectors the agent may run
    warm: list[str]                   # shell commands at image build (network allowed)
    build_env: dict[str, str] = field(default_factory=dict)
    runtime_env: dict[str, str] = field(default_factory=dict)
    extra_apt: list[str] = field(default_factory=list)
    chown: list[str] = field(default_factory=list)
    docker_prelude: list[str] = field(default_factory=list)   # e.g. COPY --from=...
    notes: dict[str, Any] = field(default_factory=dict)


class Adapter:
    """Per-language knowledge. Subclasses override the hooks below."""

    name = "base"
    track = ""
    dep_files: tuple[str, ...] = ()        # basenames (exact) whose change => skip
    dep_prefixes: tuple[str, ...] = ()     # basename prefixes (e.g. requirements)

    def is_test(self, path: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def is_source(self, path: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def is_dep_file(self, path: str) -> bool:
        b = Path(path).name
        return b in self.dep_files or (bool(self.dep_prefixes) and b.startswith(self.dep_prefixes))

    def plan(self, baseline: Path, tests: list[str], code: list[str],
             test_diff: str, siblings: list[str]) -> Plan:  # pragma: no cover - abstract
        raise NotImplementedError

    def env_plan(self, baseline: Path, code: list[str]) -> Plan:  # pragma: no cover - abstract
        """Environment-only Plan (image/build/warm) for a fix that ships no
        test of its own: oracle="" and existing=None. The agent writes the
        regression test; the verifier cross-checks it against the upstream fix."""
        raise NotImplementedError


# ---------------------------------------------------------------- helpers

# Network errors worth retrying (DNS hiccups, dropped HTTP/2 streams). A partial
# (blob:none) clone also fetches blobs lazily during diff/archive/show.
TRANSIENT_GIT_RE = re.compile(r"Could not resolve host|RPC failed|unable to access|Connection "
                              r"(reset|refused|timed out)|early EOF|unexpected disconnect|"
                              r"Operation timed out|transfer closed|SSL_ERROR|gnutls", re.I)
GIT_TRIES = 6            # backoff 20..100 s: rides out a ~5 min DNS outage


def run_git(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    """subprocess.run for git, retried with backoff on transient network errors."""
    for i in range(GIT_TRIES):
        r = subprocess.run(cmd, **kw)
        err = r.stderr if isinstance(r.stderr, str) else (r.stderr or b"").decode(errors="replace")
        if r.returncode == 0 or i == GIT_TRIES - 1 or not TRANSIENT_GIT_RE.search(err):
            return r
        time.sleep(20 * (i + 1))
    return r


def git(repo: Path, *args: str, timeout: int = 600) -> str:
    r = run_git(["git", "-C", str(repo), *args], capture_output=True, text=True,
                timeout=timeout)
    if r.returncode != 0:
        raise SkipCandidate(f"git {' '.join(args[:2])} failed: {r.stderr.strip()[:200]}")
    return r.stdout


IGNORED_DIRS = ("vendor/", "node_modules/", "dist/", "build/", "third_party/", ".github/", "docs/")


def is_ignored(path: str) -> bool:
    p = path.lower()
    return any(p.startswith(d) or f"/{d}" in p for d in IGNORED_DIRS) or p.endswith(
        (".md", ".txt", ".rst", ".min.js", ".lock", ".snap"))


def fetch(repo_url: str, sha: str, cache: Path, alt_repos: tuple[str, ...] = ()) -> Path:
    # GitHub clones keep their historical 'owner__name' cache dirs; other hosts
    # are keyed by host + path.
    dest = cache / repo_slug(repo_url).replace("/", "__")
    if not (dest / ".git").exists():
        cache.mkdir(parents=True, exist_ok=True)
        err = ""
        for url in (repo_url, *alt_repos):
            # Hosts without partial-clone support ignore --filter and send everything.
            r = run_git(["git", "clone", "--filter=blob:none", "--no-checkout", "-q",
                         url, str(dest)], capture_output=True, text=True, timeout=1800,
                        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
            if r.returncode == 0:
                break
            shutil.rmtree(dest, ignore_errors=True)
            err = r.stderr.strip()[:200]
        else:
            raise SkipCandidate(f"clone failed: {err}")
    try:
        git(dest, "cat-file", "-e", f"{sha}^{{commit}}")
    except SkipCandidate:
        git(dest, "fetch", "-q", "origin", sha)
    return dest


def changes(repo: Path, vuln: str, fix: str) -> list[Change]:
    out = []
    for ln in git(repo, "diff", "-M", "--name-status", vuln, fix).splitlines():
        parts = ln.split("\t")
        st = parts[0][:1]
        if st == "R" or st == "C":
            out.append(Change(st, parts[2], parts[1]))
        else:
            out.append(Change(st, parts[1], parts[1]))
    return out


def siblings_of(baseline: Path, tests: list[str], adapter: Adapter) -> list[str]:
    """Other test files in the same directories as the oracle tests (the
    'existing tests' check), from the vulnerable tree."""
    dirs = {str(Path(t).parent) for t in tests}
    out: list[str] = []
    for d in sorted(dirs):
        base = baseline / d
        if not base.is_dir():
            continue
        for f in sorted(base.iterdir()):
            rel = str(f.relative_to(baseline))
            if f.is_file() and adapter.is_test(rel) and rel not in tests:
                out.append(rel)
    return out[:MAX_SIBLINGS]


def q(paths) -> str:
    return " ".join(shlex.quote(p) for p in paths)


ORACLE_SH = """#!/usr/bin/env bash
# Hidden oracle: overlay the fix commit's tests onto the tree under test and
# run only them. Exit 0 iff they pass. Exit 3 = the tests did not compile/load
# (not a behavioural failure).
set -uo pipefail
cp -r "${{ORACLE_DIR:-/opt/hidden/oracle}}/files/." .
out=$( {{ {oracle} ; }} 2>&1 ); rc=$?
printf '%s\\n' "$out"
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qE {compile_re}; then
  echo "ORACLE_BUILD_FAILED"; exit 3
fi
exit $rc
"""


# The verifier + MCP server get their OWN Python (a standalone CPython built
# for glibc >= 2.17 via uv), so the project image's Python version, or lack of
# one, does not matter. Copied in at the same paths so the venv's links hold.
DOCKERFILE = """FROM python:3.11-slim-bookworm AS vpy
ENV UV_PYTHON_INSTALL_DIR=/opt/vpy PIP_DEFAULT_TIMEOUT=60 UV_HTTP_TIMEOUT=120
# Downloads from PyPI / GitHub time out now and then on the cluster: retry.
RUN for i in 1 2 3 4 5; do \\
      ( pip install --no-cache-dir --retries 5 uv && uv python install 3.11 \\
        && rm -rf /opt/venv && uv venv --python 3.11 /opt/venv \\
        && uv pip install --python /opt/venv/bin/python "jsonschema>=4.20" "pyyaml>=6.0" "mcp>=1.1,<2" ) \\
      && break; echo "vpy setup failed (attempt $i), retrying"; sleep $((i * 20)); done \\
 && /opt/venv/bin/python -c "import yaml, jsonschema, mcp" \\
 && /opt/venv/bin/python -c "import sysconfig;open(sysconfig.get_paths()['purelib']+'/defensive.pth','w').write('/opt/pkg\\\\n')"

FROM {image}
COPY --from=vpy /opt/vpy /opt/vpy
COPY --from=vpy /opt/venv /opt/venv
{prelude}# Tools the verifier needs (diff + git or patch). End-of-life Debian bases
# are retried against archive.debian.org; a failed install only fails the
# build if the tools are genuinely missing.
RUN if command -v apt-get >/dev/null; then \\
      printf 'Acquire::ForceIPv4 "true";\\nAcquire::Check-Valid-Until "false";\\n' > /etc/apt/apt.conf.d/99cvepatch; \\
      ( apt-get update || ( sed -i -e 's#deb.debian.org#archive.debian.org#g' -e 's#security.debian.org#archive.debian.org#g' -e '/-updates/d' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; apt-get update ) ) \\
      && apt-get install -y --no-install-recommends bash patch diffutils git ca-certificates {extra_apt} \\
      || echo "WARNING: apt install failed"; rm -rf /var/lib/apt/lists/*; \\
    elif command -v apk >/dev/null; then apk add --no-cache bash patch diffutils git || true; fi; \\
    command -v bash >/dev/null && command -v diff >/dev/null && (command -v git >/dev/null || command -v patch >/dev/null) \\
      || {{ echo "FATAL: image lacks bash/diff/git|patch"; exit 1; }}
COPY pkg/ /opt/pkg/
COPY baseline/ /opt/defensive/baseline/
COPY public/ /opt/defensive/task/
{build_env}# Dependencies and caches are fetched HERE (network allowed at build only).
# Each step is best-effort and logged; confirmation decides whether the
# project's tests actually run.
RUN mkdir -p /opt/cache && cd /opt/defensive/baseline && : > /opt/cache/warm.log && {warm}
RUN mkdir -p /rlenv/workspace && cp -r /opt/defensive/baseline /rlenv/src \\
 && (useradd --uid 1000 --create-home --shell /bin/bash agent 2>/dev/null || useradd --create-home --shell /bin/bash agent) \\
 && chown -R agent /rlenv/workspace /opt/cache {chown} \\
 && chmod -R a-w /rlenv/src && chmod -R a+rX /opt/defensive /opt/pkg /opt/vpy /opt/venv
USER agent
# Base-image entrypoints (e.g. maven's, which writes /root/.m2) assume root; every
# command here is explicit, so none is needed.
ENTRYPOINT []
ENV {runtime_env}DEF_SOURCE_DIR=/rlenv/src DEF_WORKSPACE_DIR=/rlenv/workspace \\
    DEF_TASK_PATH=/opt/defensive/task/defensive_task.json \\
    DEF_ALLOWED_TESTS='{{}}'
CMD ["/opt/venv/bin/python", "-m", "cvepatch.core.mcp_server.tools"]
"""


def warm_script(steps: list[str]) -> str:
    """Run each warm step in order; a failing step is logged, never fatal."""
    if not steps:
        return "true"
    return " ; ".join(
        f"( {w} ) || echo 'warm step {i} failed: {w[:60].replace(chr(39), chr(34))}' >> /opt/cache/warm.log"
        for i, w in enumerate(steps, 1))


# hidden/ must never reach the build context's COPY steps.
DOCKERIGNORE = "hidden/\nmeta.json\nconfirm_run/\nconfirm_result.json\n"

ENV_MANIFEST = """schema_version: "1"
env_id: {env_id}
interface: rl.mcp.vulnerability_defense.v1
interface_flavor: rl_mcp_v1
task_type: binary_patch
project: {lang}
bug_id: {cve}
capability_class: other
image:
  ref: {image}
  digest: null
mcp:
  episode_tools: [setup, read_file, list_directory, search_code, inspect_diff,
                  run_command, write_file, apply_patch, submit_fix, submit_report]
  evaluation_tools: [grade_defensive]
evaluate:
  kind: cli_oneshot
  command: [/opt/venv/bin/python, -m, cvepatch.core.verifier.verify,
            --run, /run, --baseline, /opt/defensive/baseline, --hidden, /opt/hidden]
  mounts:
    - {{source: hidden, target: /opt/hidden}}
  timeout_s: 7200
metadata:
  defensive_task_manifest: hidden/task.json
  generated_by: cvepatch.core.taskgen
"""


def _env_lines(env: dict[str, str], *, trailing: bool) -> str:
    if not env:
        return ""
    body = " ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())
    return f"ENV {body}\n" if not trailing else f"{body} \\\n    "


# ---------------------------------------------------------------- build
BUNDLE_FILES = ("meta.json", "Dockerfile", ".dockerignore", "env_manifest.yaml",
                "public/defensive_task.json", "hidden/task.json",
                "hidden/reference/fix.patch", "hidden/reference/test.patch")
# Left by the confirm step (root-owned inside DinD); never deleted on rebuild.
CONFIRM_LEFTOVERS = ("pkg", "confirm_run", "confirm_result.json")


def bundle_complete(out: Path) -> bool:
    """meta.json is written last, so its presence (plus the rest) marks a full bundle."""
    return all((out / f).is_file() for f in BUNDLE_FILES) and any((out / "baseline").iterdir())


def build_task(cve: str, commit: str | CommitRef, cache: Path, out_root: Path,
               adapter: Adapter, reuse: bool = True,
               advisory: dict[str, Any] | None = None, keep_all: bool = False,
               allow_no_code: bool = True) -> dict[str, Any]:
    """Write the task bundle for one CVE fix commit.

    keep_all: never drop a CVE for being hard to grade; record why in
    metadata.labels instead (dependency change, renamed test, no code change in
    the commit, unsupported build -> agent setup). Only a missing vulnerable
    version (root commit) or a git/clone failure still skips."""
    if advisory:   # advisories.jsonl may predate deep scrubbing
        advisory = scrub_advisory(advisory)
    task_id = f"{adapter.name}-{cve.lower()}"
    out = out_root / task_id
    if reuse and out.is_dir() and bundle_complete(out):
        # Never rewrite a bundle that may already be confirmed.
        return {"task_id": task_id, "reused": True, **json.loads((out / "meta.json").read_text())}
    cref = commit if isinstance(commit, CommitRef) else parse_commit_url(commit)
    if cref is None:
        raise SkipCandidate("no commit URL")
    repo_url, short = cref.repo, cref.sha
    repo = fetch(repo_url, short, cache, cref.alt_repos)
    fix = git(repo, "rev-parse", f"{short}^{{commit}}").strip()
    parents = git(repo, "rev-list", "--parents", "-n1", fix).split()
    if len(parents) < 2:
        raise SkipCandidate("fix commit is a root commit")
    vuln = parents[1]   # first parent; for merges this is the mainline side

    chs = changes(repo, vuln, fix)
    labels: dict[str, Any] = {}
    if any(adapter.is_dep_file(c.path) or adapter.is_dep_file(c.old) for c in chs):
        if not keep_all:
            raise SkipCandidate("fix changes dependency manifests (can't grade offline)")
        labels["deps_changed"] = True
    tests = [c.path for c in chs if adapter.is_test(c.path) and c.status != "D"]
    if any(c.status == "R" and adapter.is_test(c.old) for c in chs):
        if not keep_all:
            raise SkipCandidate("fix renames a test file")
        labels["test_renamed"] = True
    code_changes = [c for c in chs if adapter.is_source(c.path) and not adapter.is_test(c.path)
                    and not is_ignored(c.path)]
    if not code_changes:
        if not keep_all:
            raise SkipCandidate("fix commit has no non-test source changes")
        if not allow_no_code:
            raise NoCodeFix("fix commit has no non-test source changes")
        # Keep it: the reference is whatever non-test change the commit made.
        labels["ref"] = "no_code_fix"
        code_changes = [c for c in chs if not adapter.is_test(c.path)]
    # A fix with no test of its own still makes a task: the agent writes the
    # regression test, and the verifier cross-checks it against this upstream
    # fix (tier T2) — no upstream oracle (no T1). Guarded by env_plan().
    has_oracle = bool(tests)
    code = [c.path for c in code_changes]
    code_specs = sorted({p for c in code_changes for p in (c.path, c.old)})

    # Remove what we own; confirm-step leftovers may remain (recreated by it).
    for child in (out.iterdir() if out.is_dir() else []):
        if child.name not in CONFIRM_LEFTOVERS:
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    (out / "baseline").mkdir(parents=True)
    hidden = out / "hidden"
    try:
        arc = run_git(["git", "-C", str(repo), "archive", vuln], capture_output=True,
                             timeout=1800)
        if arc.returncode != 0:
            raise SkipCandidate("git archive failed")
        subprocess.run(["tar", "-x", "-C", str(out / "baseline")], input=arc.stdout, check=True)

        def planned(make):
            try:
                return make(adapter)
            except SkipCandidate as e:
                if not keep_all or labels.get("env") == "agent_setup":
                    raise
                # No builder for this layout: an agent sets it up instead.
                from cvepatch.core.taskgen.setup_adapters import fallback_for
                labels.update(env="agent_setup", builder_skip=str(e)[:200])
                return make(fallback_for(adapter))

        if has_oracle:
            test_diff = git(repo, "diff", "--no-color", vuln, fix, "--", *tests)
            sibs = siblings_of(out / "baseline", tests, adapter)
            plan = planned(lambda ad: ad.plan(out / "baseline", tests, code, test_diff, sibs))
            (hidden / "oracle" / "files").mkdir(parents=True)
            for p in tests:
                dst = hidden / "oracle" / "files" / p
                dst.parent.mkdir(parents=True, exist_ok=True)
                shown = run_git(["git", "-C", str(repo), "show", f"{fix}:{p}"], capture_output=True)
                if shown.returncode != 0:
                    raise SkipCandidate(f"git show failed: {shown.stderr.decode(errors='replace')[:200]}")
                dst.write_bytes(shown.stdout)
            (hidden / "oracle" / "run.sh").write_text(ORACLE_SH.format(
                oracle=plan.oracle, compile_re=shlex.quote(plan.compile_fail_re)))
        else:
            test_diff = ""
            sibs = []
            plan = planned(lambda ad: ad.env_plan(out / "baseline", code))
            hidden.mkdir(parents=True, exist_ok=True)

        ref = git(repo, "diff", "-M", "--no-color", vuln, fix, "--", *code_specs) if code_specs else ""
        if not ref.strip():
            if not keep_all:
                raise SkipCandidate("empty reference patch")
            labels["ref"] = "empty"
        (hidden / "reference").mkdir()
        (hidden / "reference" / "fix.patch").write_text(ref)
        (hidden / "reference" / "test.patch").write_text(test_diff)
    except BaseException:
        for f in ("baseline", "hidden"):
            shutil.rmtree(out / f, ignore_errors=True)
        if not any(out.iterdir()):
            out.rmdir()
        raise

    meta = {"cve": cve, "lang": adapter.name, "repo": repo_url, "fix_commit": fix,
            "vulnerable_commit": vuln, "merge_fix": len(parents) > 2,
            "oracle_files": tests, "existing_files": sibs, "patched_files": code,
            "has_oracle": has_oracle, "labels": labels,
            "image": plan.image, "has_advisory": advisory is not None, **plan.notes}
    _write_bundle(out, task_id, cve, repo_url, fix, vuln, ref, plan, adapter, meta, advisory)
    return {"task_id": task_id, **meta}


def public_task(full: dict[str, Any], cve: str, now: str) -> dict[str, Any]:
    """The task as the agent may see it: everything that points at the fix
    (commit, provenance, evidence URLs, build/test commands, oracle and sibling
    file names) is removed. Still schema-valid."""
    pub = json.loads(json.dumps(full))
    pub.update({
        "fixed_commit": None, "patch_commit": None,
        "patch_provenance": {"status": "unknown"},
        "build_instructions": {"mode": "reproducible", "command": ["true"], "workdir": None,
                               "timeout_s": 60, "toolchain": full["build_instructions"].get("toolchain")},
        "regression_test_command": {"command": ["true"], "workdir": None, "timeout_s": 60,
                                    "invariant": "Run by the verifier, not in the episode."},
        "existing_test_command": None,
        "validation_strategy": "regression",
        "evidence": [{"kind": "cve_record", "source": f"https://www.cve.org/CVERecord?id={cve}",
                      "retrieved_at": now, "content_sha256": None, "note": None}],
        "limitations": [],
        "metadata": {k: full["metadata"][k] for k in ("ecosystem", "checkout_mode", "advisory")
                     if k in full["metadata"]},
    })
    return pub


def _write_bundle(out: Path, task_id: str, cve: str, repo_url: str, fix: str, vuln: str,
                  ref: str, plan: Plan, adapter: Adapter, meta: dict,
                  advisory: dict[str, Any] | None = None) -> None:
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    src = f"{repo_url}/commit/{fix}"
    adv = advisory or {}
    manifest = {
        "schema_version": "1", "task_id": task_id, "task_type": "vulnerability_defense",
        "cve_id": cve, "chromium_issue_id": None,
        "product": repo_slug(repo_url), "component": adapter.name,
        "vulnerability_class": (adv.get("cwe_ids") or ["see advisory"])[0],
        "cwe_ids": list(adv.get("cwe_ids") or []), "affected_versions": [],
        "vulnerable_commit": vuln, "fixed_commit": fix, "source_repository": repo_url,
        "patch_commit": fix,
        "patch_provenance": {"status": "verified", "source": src,
                             "content_sha256": sha256_text(ref), "retrieved_at": now,
                             "note": "Upstream fix commit (non-test source files) linked from the CVE record."},
        "build_instructions": {"mode": "reproducible", "command": plan.build, "workdir": None,
                               "timeout_s": 1800, "toolchain": {"image": plan.image}},
        "regression_test_command": ({"command": ["bash", "/opt/hidden/oracle/run.sh"],
                                     "workdir": None, "timeout_s": 1800,
                                     "invariant": "Tests added/changed by the upstream fix pass (exit 0)."}
                                    if meta["has_oracle"] else
                                    {"command": ["true"], "workdir": None, "timeout_s": 1800,
                                     "invariant": "No upstream test; the agent's own regression test is the oracle."}),
        "existing_test_command": ({"command": plan.existing, "workdir": None, "timeout_s": 1800}
                                  if plan.existing else None),
        "security_checks": [],
        "validation_strategy": "regression_plus_existing" if plan.existing else "regression",
        "patched_files_allowlist": [],
        "expected_baseline_result": "regression_fail", "expected_patched_result": "regression_pass",
        "resource_limits": {"cpu": 3600, "memory_mb": None, "pids": 4096, "wallclock_s": 3600},
        "network_policy": "none", "task_status": "CLASSIFIED",
        "evidence": [{"kind": "commit", "source": src, "retrieved_at": now,
                      "content_sha256": sha256_text(ref),
                      "note": f"fix commit for {cve}; vulnerable = first parent {vuln}"}],
        "limitations": (["Oracle is the upstream fix's own tests; they may not cover every variant of the bug."]
                        if meta["has_oracle"] else
                        ["No upstream test: the fix ships none. The agent writes the regression "
                         "test; it is cross-checked against the upstream fix (tier T2 ceiling, no T1)."])
        + ([] if plan.existing else ["No sibling tests found; existing-test check not run."]),
        "metadata": {"ecosystem": adapter.name, "checkout_mode": "copy",
                     "has_oracle": meta["has_oracle"],
                     "oracle_files": meta["oracle_files"], "oracle_command": plan.oracle,
                     "compile_fail_re": plan.compile_fail_re,
                     # agent_setup.py and confirmation read this from task.json
                     **({"setup_mode": plan.notes["setup_mode"]} if "setup_mode" in plan.notes else {}),
                     "labels": meta.get("labels") or {},
                     **({"advisory": advisory} if advisory else {})},
    }
    (out / "hidden" / "task.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "public").mkdir(exist_ok=True)
    (out / "public" / "defensive_task.json").write_text(
        json.dumps(public_task(manifest, cve, now), indent=2) + "\n")
    env_id = f"defensive-{task_id}"
    image_ref = f"local/defensive-{task_id}:latest"
    (out / "env_manifest.yaml").write_text(ENV_MANIFEST.format(
        env_id=env_id, lang=adapter.name, cve=cve, image=image_ref))
    (out / ".dockerignore").write_text(DOCKERIGNORE)
    (out / "Dockerfile").write_text(DOCKERFILE.format(
        image=plan.image,
        prelude="".join(ln + "\n" for ln in plan.docker_prelude),
        extra_apt=" ".join(plan.extra_apt),
        build_env=_env_lines(plan.build_env, trailing=False),
        warm=warm_script(plan.warm),
        chown=" ".join(plan.chown),
        runtime_env=_env_lines({**plan.build_env, **plan.runtime_env}, trailing=True),
    ))
    (out / "meta.json").write_text(json.dumps({**meta, "env_id": env_id, "created_at": now},
                                              indent=2) + "\n")
