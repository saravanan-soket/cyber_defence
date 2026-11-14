#!/usr/bin/env python3
"""Container step: build each task image and confirm it with the verifier.

Runs where `docker` is available (the DinD Job). For every bundle written by
taskgen.py (any language):
  1. build the task image (dependencies fetched here, at build time);
  2. run the production verifier on the REFERENCE solution: the upstream fix
     as the "fix" and the upstream tests as the "regression test", in a fresh
     container with --network none and hidden/ mounted read-only, exactly as
     an agent's submission is verified;
  3. accept the task (REPRODUCIBLE) only if that comes out tier T1: the
     upstream tests fail on the vulnerable tree (for a behavioural reason, not
     a compile error) and pass with the fix, and existing tests pass.

Results go to <out>/confirm.jsonl; accepted tasks get registered.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from cvepatch.core.verifier.verify import VERIFIER_VERSION  # noqa: E402

# Per-container memory cap. Builds and tests share the DinD pod's 32Gi limit;
# without a cap one heavy build OOM-kills the daemon and every later bundle fails.
MEM = "16g"
# CPU pinning. The pod's CPU limit is a quota, so nproc still reports every core
# on the node and `go build`, cargo, etc. start one worker per core; on a big
# node that alone exceeds MEM. A cpuset caps their parallelism. It must be a
# subset of the CPUs this pod may use (the kubelet hands some cores to other
# pods exclusively), read at call time because that set changes.
NCPUS = 8


# Written by the DinD container at start (deploy/kube/*.yaml): the daemon's own
# allowed CPU list, e.g. "0-3,6-11,14-17".
DIND_CPUS = Path("/dind/dind.cpus")


def parse_cpu_list(text: str) -> list[int]:
    cpus: list[int] = []
    for part in text.strip().split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit():
            cpus += range(int(lo), int(hi or lo) + 1)
    return sorted(set(cpus))


def cpu_args() -> list[str]:
    try:
        cpus = parse_cpu_list(DIND_CPUS.read_text()) if DIND_CPUS.is_file() \
            else sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError, ValueError):
        return []
    if not cpus:
        return []
    # Several worker pods share a node and each sees the same allowed set: give
    # each one a different slice (by its Job index) instead of all taking the first 8.
    start = int(os.environ.get("JOB_COMPLETION_INDEX", "0") or 0) * NCPUS % len(cpus)
    pick = (cpus[start:] + cpus[:start])[:NCPUS]
    return ["--cpuset-cpus", ",".join(map(str, sorted(pick)))]


def docker_alive() -> bool:
    try:
        return sh(["docker", "info"], timeout=30).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def sh(cmd: list[str], timeout: int, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)


def refresh_vpy_stage(bundle: Path) -> None:
    """Rewrite the bundle's first build stage (our verifier's Python) to the
    current template, so bundles written before a fix to it get the fix too."""
    from cvepatch.core.taskgen.core import DOCKERFILE
    df = bundle / "Dockerfile"
    try:
        text = df.read_text()
    except OSError:
        return
    stage = DOCKERFILE.split("FROM {image}")[0].rstrip("\n") + "\n"
    if not text.startswith("FROM python:3.11-slim-bookworm AS vpy") or text.startswith(stage):
        return
    rest = text[text.index("\nFROM ", 10) + 1:]
    df.write_text(stage + rest)


def stage_pkg(bundle: Path) -> None:
    refresh_vpy_stage(bundle)
    pkg = bundle / "pkg" / "cvepatch"
    if pkg.exists():
        shutil.rmtree(bundle / "pkg")
    pkg.mkdir(parents=True)
    shutil.copy(REPO / "cvepatch" / "__init__.py", pkg / "__init__.py")
    shutil.copytree(REPO / "cvepatch" / "core", pkg / "core",
                    ignore=shutil.ignore_patterns("__pycache__"))


def reference_submission(bundle: Path) -> dict:
    """The upstream fix + tests, shaped like an agent's submit_fix result."""
    task = json.loads((bundle / "hidden" / "task.json").read_text())
    meta = task["metadata"]
    return {"ok": True, "accepted": True,
            "test_files": meta["oracle_files"], "test_command": meta["oracle_command"],
            "test_patch": (bundle / "hidden" / "reference" / "test.patch").read_text(),
            "fix_patch": (bundle / "hidden" / "reference" / "fix.patch").read_text()}


def _build_check(bundle: Path, image: str, task: dict) -> dict:
    """Apply the reference fix in a fresh container and run the build command
    (and the existing tests, when the task has them: agent-setup tasks)."""
    build = (task.get("build_instructions") or {}).get("command")
    if not build:
        return {"status": "BUILDABLE", "reason": "image builds; no build command to check"}
    existing = (task.get("existing_test_command") or {}).get("command")
    script = ("set -e; cp -r /opt/defensive/baseline /tmp/src && cd /tmp/src && "
              "git apply -p1 /opt/hidden/reference/fix.patch 2>/dev/null "
              "|| patch -p1 < /opt/hidden/reference/fix.patch; " + shlex.join(build)
              + (f" && {shlex.join(existing)}" if existing else ""))
    cmd = ["docker", "run", "--rm", "--network", "none", "--pids-limit", "4096",
           "--memory", MEM, *cpu_args(),
           "-v", f"{(bundle / 'hidden').resolve()}:/opt/hidden:ro", image,
           "bash", "-c", script]
    try:
        r = sh(cmd, timeout=3600)
    except subprocess.TimeoutExpired:
        return {"status": "FAILED", "reason": "build check timed out"}
    if r.returncode == 0:
        return {"status": "BUILDABLE",
                "reason": "image builds; upstream fix applies and the project builds "
                          "(no upstream test; agent writes the regression test)"}
    return {"status": "INCONCLUSIVE",
            "reason": "upstream fix does not build in the image"
                      + (" or the existing tests fail with it, offline" if existing else ""),
            "log": ((r.stdout or '') + (r.stderr or ''))[-600:]}


def confirm(bundle: Path) -> dict:
    task_id = bundle.name
    image = f"local/defensive-{task_id}:latest"
    rec: dict = {"task_id": task_id, "verifier": VERIFIER_VERSION}
    if not (bundle / "hidden" / "task.json").is_file():
        return rec | {"status": "FAILED", "reason": "old bundle layout; rerun taskgen.py"}
    t0 = time.monotonic()
    task = json.loads((bundle / "hidden" / "task.json").read_text())
    if task["metadata"].get("setup_mode") == "agent":
        # The image is the one scripts/agent_setup.py saved; rebuilding from
        # the Dockerfile would give back the bare toolchain image.
        sr = bundle / "setup_result.json"
        st = json.loads(sr.read_text()).get("status") if sr.is_file() else None
        if st != "SETUP_OK":
            return rec | {"status": "NEEDS_SETUP",
                          "reason": f"agent setup not done ({st or 'not run'}); run agent_setup.py"}
        if sh(["docker", "image", "inspect", image], timeout=60).returncode != 0:
            return rec | {"status": "NEEDS_SETUP", "reason": "setup image missing; rerun agent_setup.py --retry"}
        rec["on_setup_image"] = True
    else:
        stage_pkg(bundle)
        try:
            b = sh(["docker", "build", "-q", "--memory", MEM, *cpu_args(),
                    "-t", image, str(bundle)], timeout=3600)
        except subprocess.TimeoutExpired:
            return rec | {"status": "FAILED", "reason": "image build timed out"}
        if b.returncode != 0:
            tail = ((b.stdout or '') + (b.stderr or ''))[-600:]
            return rec | {"status": "FAILED", "reason": "image build failed", "log": tail}
    rec["build_s"] = round(time.monotonic() - t0)

    if not task["metadata"].get("has_oracle", True):
        # No upstream test -> can't verify the reference as T1. Prove the task
        # is usable: the reference fix applies and the project builds. The
        # agent supplies the regression test at run time (verifier tier <= T2).
        rec["total_s"] = round(time.monotonic() - t0)
        out = _build_check(bundle, image, task)
        rec |= out
        return rec

    run_dir = bundle / "confirm_run"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir()
    sub = reference_submission(bundle)
    (run_dir / "tool_calls.jsonl").write_text(json.dumps(
        {"tool": "submit_fix", "args": {"test_files": sub["test_files"],
                                        "test_command": sub["test_command"]},
         "result": json.dumps(sub)}) + "\n")
    cmd = ["docker", "run", "--rm", "--network", "none", "--pids-limit", "4096",
           "--memory", MEM, *cpu_args(),
           "-v", f"{run_dir.resolve()}:/run:ro",
           "-v", f"{(bundle / 'hidden').resolve()}:/opt/hidden:ro", image,
           "/opt/venv/bin/python", "-m", "cvepatch.core.verifier.verify",
           "--run", "/run", "--baseline", "/opt/defensive/baseline", "--hidden", "/opt/hidden"]
    try:
        g = sh(cmd, timeout=7200)
    except subprocess.TimeoutExpired:
        return rec | {"status": "FAILED", "reason": "verification timed out"}
    rec["total_s"] = round(time.monotonic() - t0)
    try:
        res = json.loads(g.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return rec | {"status": "FAILED", "reason": "verifier output not JSON",
                      "log": ((g.stdout or '') + (g.stderr or ''))[-600:]}
    (bundle / "confirm_result.json").write_text(json.dumps(res, indent=2))
    try:
        w = sh(["docker", "run", "--rm", "--network", "none", image, "cat", "/opt/cache/warm.log"],
               timeout=120)
        rec["warm_failed"] = [ln for ln in w.stdout.splitlines() if ln.strip()][:10]
    except subprocess.TimeoutExpired:
        pass
    c = res.get("checks") or {}
    rec["tier"] = res.get("tier")
    rec["checks"] = {k: v for k, v in c.items() if v is not None}
    if res.get("tier") == "T1":
        return rec | {"status": "REPRODUCIBLE",
                      "reason": "upstream tests fail on vulnerable code, pass with the fix; "
                                "existing tests pass"}
    steps = {s["name"]: s for s in res.get("steps", [])}
    compile_fail = any("does not compile" in (s.get("detail") or "") for s in steps.values())
    if res.get("capabilities", {}).get("infrastructure_failure"):
        return rec | {"status": "FAILED", "reason": "; ".join(res.get("failure_reasons", []))[:300]}
    if not c.get("fix_applies") or not c.get("test_applies"):
        reason = "reference fix/test does not apply to the baseline"
    elif compile_fail:
        reason = "oracle tests do not compile on the baseline (need new API)"
    elif c.get("upstream_test_fails_on_vuln") is False:
        reason = "oracle passes on the vulnerable baseline (does not detect the bug)"
    elif c.get("candidate_build_passed") is False:
        reason = "upstream fix does not build in the image"
    elif c.get("upstream_test_passes_on_fix") is False:
        reason = "upstream fix does not pass the oracle"
    elif c.get("existing_tests_passed") is False:
        reason = "existing tests fail with the upstream fix (flaky or environment)"
    elif None in (c.get("upstream_test_fails_on_vuln"), c.get("upstream_test_passes_on_fix")):
        reason = "oracle timed out"
    else:
        reason = "; ".join(res.get("failure_reasons", []))[:300] or f"tier {res.get('tier')}"
    if reason in TEST_ONLY_PROBLEMS or (c.get("fix_applies") and not c.get("test_applies")):
        # The upstream TEST is unusable, not the fix: keep the task without it.
        demoted = demote_oracle(bundle, image, reason)
        if demoted is not None:
            return rec | demoted
    return rec | {"status": "INCONCLUSIVE", "reason": reason}


# Problems with the upstream test alone; the fix may still make a good task
# where the agent writes the regression test (verifier tier <= T2).
TEST_ONLY_PROBLEMS = {
    "oracle tests do not compile on the baseline (need new API)",
    "oracle passes on the vulnerable baseline (does not detect the bug)",
    "upstream fix does not pass the oracle",
}


def demote_oracle(bundle: Path, image: str, why: str) -> dict | None:
    """Drop an unusable upstream test: if the reference fix applies and builds and
    the existing tests pass with it, the task becomes a no-oracle (BUILDABLE) task.
    hidden/oracle is moved aside so the verifier no longer runs it."""
    tpath = bundle / "hidden" / "task.json"
    task = json.loads(tpath.read_text())
    chk = _build_check(bundle, image, task)
    if chk["status"] != "BUILDABLE":
        return None
    oracle, aside = bundle / "hidden" / "oracle", bundle / "hidden" / "oracle.unusable"
    if oracle.exists():
        shutil.rmtree(aside, ignore_errors=True)
        oracle.rename(aside)
    meta = task["metadata"]
    meta.update(has_oracle=False, oracle_dropped=why)
    task["regression_test_command"] = {
        "command": ["true"], "workdir": None, "timeout_s": 1800,
        "invariant": "Upstream test unusable; the agent's own regression test is the oracle."}
    task.setdefault("limitations", []).append(
        f"Upstream test dropped ({why}); the agent writes the regression test (tier T2 ceiling).")
    tpath.write_text(json.dumps(task, indent=2) + "\n")
    return {"status": "BUILDABLE", "oracle_dropped": why,
            "reason": f"upstream test unusable ({why}); fix applies and builds, existing tests pass"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True, help="dir with task bundles")
    ap.add_argument("--register", action="store_true")
    ap.add_argument("--prune-images", action="store_true",
                    help="remove each rejected image to save disk")
    ap.add_argument("--only-failed", action="store_true",
                    help="retry bundles whose previous result was FAILED")
    ap.add_argument("--only-new", action="store_true",
                    help="confirm bundles with no result from the current verifier version "
                         "(combines with --only-failed)")
    a = ap.parse_args()
    # Bundles directly under --out, or one level down (<out>/<lang>/<bundle>).
    bundles = sorted({p.parent for p in a.out.glob("Dockerfile")} |
                     {p.parent for p in a.out.glob("*/Dockerfile")} |
                     {p.parent for p in a.out.glob("*/*/Dockerfile")})
    prev_path = a.out / "confirm.jsonl"
    prev = {}
    if prev_path.exists():
        for ln in prev_path.read_text().splitlines():
            r = json.loads(ln)
            prev[r["task_id"]] = r
    def stale_setup(b: Path) -> bool:
        """A setup-mode bundle whose last result predates its setup image."""
        try:
            setup = json.loads((b / "hidden" / "task.json").read_text())["metadata"].get("setup_mode")
        except (OSError, ValueError, KeyError):
            return False
        return setup == "agent" and not prev.get(b.name, {}).get("on_setup_image")

    if a.only_failed or a.only_new:
        bundles = [b for b in bundles
                   if (a.only_new and (prev.get(b.name, {}).get("verifier") != VERIFIER_VERSION
                                       or prev.get(b.name, {}).get("status") == "NEEDS_SETUP"))
                   or (a.only_failed and prev.get(b.name, {}).get("status") == "FAILED")
                   or stale_setup(b)]
    stats = Counter()
    aborted = False
    results = dict(prev)
    with (a.out / "confirm.run.jsonl").open("w") as log:
        for i, b in enumerate(bundles, 1):
            try:
                rec = confirm(b)
            except Exception as e:  # noqa: BLE001
                rec = {"task_id": b.name, "status": "FAILED", "reason": f"{type(e).__name__}: {e}"}
            if rec["status"] == "FAILED" and not docker_alive():
                # Don't record infra failures as task failures: the unfinished
                # bundles keep no result, so the next run picks them up.
                print(f"[{i}/{len(bundles)}] {b.name}: docker daemon is gone; stopping",
                      file=sys.stderr, flush=True)
                aborted = True
                break
            # REPRODUCIBLE (upstream oracle, T1) and BUILDABLE (no oracle, but
            # the image builds and the fix compiles) are both runnable tasks:
            # register them and keep their images for the run Job to reuse.
            runnable = rec["status"] in ("REPRODUCIBLE", "BUILDABLE")
            if runnable and a.register:
                r = sh(["cvepatch", "register-defensive", str(b / "env_manifest.yaml")],
                       timeout=120)
                rec["registered"] = r.returncode == 0
            elif a.prune_images and not runnable:
                sh(["docker", "rmi", "-f", f"local/defensive-{b.name}:latest"], timeout=300)
            stats[rec["status"]] += 1
            results[rec["task_id"]] = rec
            log.write(json.dumps(rec) + "\n")
            log.flush()
            print(f"[{i}/{len(bundles)}] {b.name}: {rec['status']} - {rec.get('reason','')[:90]}",
                  file=sys.stderr, flush=True)
    # confirm.jsonl keeps the latest result per bundle across runs.
    prev_path.write_text("".join(json.dumps(r) + "\n" for r in results.values()))
    overall = Counter(r["status"] for r in results.values())
    summary = {"this_run": {"bundles": len(bundles), "by_status": dict(stats)},
               "all_bundles": dict(overall)}
    (a.out / "confirm_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 1 if aborted else 0


if __name__ == "__main__":
    raise SystemExit(main())
