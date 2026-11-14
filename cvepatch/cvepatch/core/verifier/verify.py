"""cvepatch verifier: label an agent's fix + regression test with a quality tier.

Runs in a FRESH container after the episode, with the run dir and the task's
hidden material mounted read-only:

    docker run --rm --network none -v <run>:/run:ro -v <bundle>/hidden:/opt/hidden:ro \
        <image> python -m cvepatch.core.verifier.verify \
          --run /run --baseline /opt/defensive/baseline --hidden /opt/hidden

The agent's submission (last `submit_fix` call in tool_calls.jsonl) is a fix
diff, a test diff and the command that runs the test. Checks:

  agent_test_fails_on_vuln          test fails on the vulnerable tree (every repeat),
                                    and not because it doesn't compile there
  agent_test_passes_on_fix          test passes with the agent's fix (every repeat)
  existing_tests_passed             the project's existing tests still pass
  upstream_test_{fails_on_vuln,passes_on_fix}
                                    the upstream fix's own tests (hidden/oracle)
  agent_test_passes_on_upstream_fix the agent's test also passes on the hidden
                                    upstream fix: it tests the bug, not the agent's
                                    particular patch
  agent_test_passes_on_fixed_release  same, against a fixed release tree

Tier: base = fix/test apply, build ok, fails on vuln, passes on fix, existing
tests not failing. T1 = base + upstream tests pass on the agent's fix;
T2 = base + agent test passes on the upstream fix; T3 = base + passes on the
fixed release; T4 = base only; otherwise "rejected". Executable checks only;
no LLM is involved.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from cvepatch.core import manifest as task_manifest
from cvepatch.core.oracle.base import CommandResult, ResourceLimits, run_command
from cvepatch.core.report import evaluate_report
from cvepatch.core.validation.patch_validator import (
    PatchValidationError,
    apply_patch_to_tree,
    validate_patch,
)
from cvepatch.core.validation.pipeline import git_reset_tree
from cvepatch.core.verifier.deterministic_grader import _find_report

VERIFIER_VERSION = "cvepatch-verifier-1.0.0"
TIERS = ("T1", "T2", "T3", "T4", "rejected")
CHECKS = (
    "fix_applies", "test_applies", "candidate_build_passed",
    "agent_test_fails_on_vuln", "agent_test_passes_on_fix", "existing_tests_passed",
    "upstream_test_fails_on_vuln", "upstream_test_passes_on_fix",
    "agent_test_passes_on_upstream_fix", "agent_test_passes_on_fixed_release",
)
DEFAULT_TEST_TIMEOUT_S = 1800
EXCERPT = 1500


# ----------------------------------------------------------------- submission
def find_submission(run_dir: Path) -> dict[str, Any] | None:
    """Last successful `submit_fix` call: {test_files, test_command, test_patch, fix_patch}."""
    log = run_dir / "tool_calls.jsonl"
    found = None
    if not log.is_file():
        return None
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("tool") != "submit_fix":
            continue
        res = entry.get("result")
        if isinstance(res, str):
            try:
                res = json.loads(res)
            except json.JSONDecodeError:
                continue
        if isinstance(res, dict) and res.get("ok") and res.get("fix_patch") and res.get("test_patch"):
            found = res
    return found


# ---------------------------------------------------------------------- trees
class Trees:
    """Fresh copies of the vulnerable tree (copy mode) or the tree itself,
    reset between uses (git mode, for trees too large to copy)."""

    def __init__(self, baseline: Path, work_root: Path, mode: str) -> None:
        self.baseline, self.work_root, self.mode = baseline, work_root, mode

    def fresh(self, name: str, base: Path | None = None) -> Path:
        src = base or self.baseline
        if self.mode == "git" and base is None:
            git_reset_tree(src)
            return src
        dst = self.work_root / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=True)
        return dst

    def done(self) -> None:
        if self.mode == "git":
            git_reset_tree(self.baseline)


def _apply(text: str, tree: Path, allowlist: tuple[str, ...] = ()) -> tuple[bool, str]:
    try:
        info = validate_patch(text, allowlist=allowlist, require_nonempty=True)
    except PatchValidationError as exc:
        return False, f"invalid diff: {exc}"
    if info.disallowed:
        return False, f"touches files outside the allowlist: {list(info.disallowed)}"
    res = apply_patch_to_tree(info, tree)
    return res.ok, res.detail


# ------------------------------------------------------------------- verifier
class Verifier:
    def __init__(self, *, run_dir: Path, baseline: Path, hidden: Path,
                 work_root: Path, repeats: int = 2) -> None:
        self.run_dir, self.baseline, self.hidden = run_dir, baseline, hidden
        task_path = hidden / "task.json"
        self.task = task_manifest.load(task_path)
        self.meta = self.task.raw.get("metadata") or {}
        self.limits = ResourceLimits.from_task(self.task.resource_limits)
        self.trees = Trees(baseline, work_root, self.task.checkout_mode)
        self.repeats = max(1, repeats)
        self.compile_re = re.compile(self.meta["compile_fail_re"]) \
            if self.meta.get("compile_fail_re") else None
        rt = self.task.regression_test_command or {}
        self.test_timeout = int(rt.get("timeout_s") or DEFAULT_TEST_TIMEOUT_S)
        self.checks: dict[str, bool | None] = dict.fromkeys(CHECKS)
        self.steps: list[dict[str, Any]] = []
        self.reasons: list[str] = []

    # -- helpers
    def _step(self, name: str, ok: bool | None, detail: str = "",
              res: CommandResult | None = None) -> None:
        rec: dict[str, Any] = {"name": name, "ok": ok, "detail": detail[:500]}
        if res is not None:
            rec |= {"exit_code": res.exit_code, "timed_out": res.timed_out,
                    "duration_s": res.duration_s,
                    "output_excerpt": (res.stdout + res.stderr)[-EXCERPT:]}
        self.steps.append(rec)

    def _sh(self, cmd: str, tree: Path, env: dict[str, str] | None = None) -> CommandResult:
        return run_command(["bash", "-c", cmd], cwd=tree, timeout_s=self.test_timeout,
                           env=env, limits=self.limits)

    def _test_runs(self, name: str, cmd: str, tree: Path, *, want_pass: bool,
                   env: dict[str, str] | None = None) -> bool | None:
        """Run `cmd` `repeats` times; True iff every run has the wanted outcome.
        None when a run timed out (inconclusive)."""
        for i in range(self.repeats):
            r = self._sh(cmd, tree, env)
            if r.timed_out:
                self._step(f"{name}#{i + 1}", None, "timed out", r)
                return None
            passed = r.exit_code == 0
            if not want_pass and not passed and self.compile_re is not None \
                    and self.compile_re.search(r.stdout + r.stderr):
                self._step(f"{name}#{i + 1}", False,
                           "fails only because the test does not compile here", r)
                return False
            ok = passed == want_pass
            self._step(f"{name}#{i + 1}", ok, "", r)
            if not ok:
                return False
        return True

    def _build(self, tree: Path) -> bool | None:
        bi = self.task.build_instructions or {}
        argv = bi.get("command")
        if not argv:
            return None
        cwd = tree / bi["workdir"] if bi.get("workdir") else tree
        r = run_command(argv, cwd=cwd, timeout_s=int(bi.get("timeout_s", 1800)),
                        limits=self.limits)
        ok = r.exit_code == 0 and not r.timed_out
        self._step("build", ok, "", r)
        return ok

    def _existing(self, tree: Path) -> bool | None:
        spec = self.task.existing_test_command
        if not spec:
            return None
        cwd = tree / spec["workdir"] if spec.get("workdir") else tree
        r = run_command(spec["command"], cwd=cwd,
                        timeout_s=int(spec.get("timeout_s", DEFAULT_TEST_TIMEOUT_S)),
                        limits=self.limits)
        ok = r.exit_code == 0 and not r.timed_out
        self._step("existing_tests", ok, "", r)
        return ok

    # -- main
    def run(self) -> dict[str, Any]:
        sub = find_submission(self.run_dir)
        if sub is None:
            self.reasons.append("no successful submit_fix call in the transcript")
            return self._result(None)
        fix, test, cmd = sub["fix_patch"], sub["test_patch"], sub["test_command"]
        allow = tuple(self.task.patched_files_allowlist)
        c = self.checks

        # 1. vulnerable + agent test -> must fail
        vt = self.trees.fresh("vuln_test")
        c["test_applies"], d = _apply(test, vt)
        self._step("apply_test_on_vuln", c["test_applies"], d)
        if c["test_applies"]:
            c["agent_test_fails_on_vuln"] = self._test_runs(
                "agent_test_on_vuln", cmd, vt, want_pass=False)

        # 2. agent fix + agent test -> build, must pass; existing tests pass
        ft = self.trees.fresh("fix_test")
        c["fix_applies"], d = _apply(fix, ft, allow)
        self._step("apply_fix", c["fix_applies"], d)
        if c["fix_applies"] and c["test_applies"]:
            ok, d = _apply(test, ft)
            if not ok:
                self._step("apply_test_on_fix", False, d)
                c["agent_test_passes_on_fix"] = False
            else:
                c["candidate_build_passed"] = self._build(ft)
                if c["candidate_build_passed"] is not False:
                    c["agent_test_passes_on_fix"] = self._test_runs(
                        "agent_test_on_fix", cmd, ft, want_pass=True)
                    c["existing_tests_passed"] = self._existing(ft)

        # 3. upstream (hidden) tests against vuln and against the agent's fix
        oracle = self.hidden / "oracle" / "run.sh"
        if oracle.is_file():
            env = {"ORACLE_DIR": str(self.hidden / "oracle")}
            run = f"bash {oracle}"
            vo = self.trees.fresh("vuln_oracle")
            c["upstream_test_fails_on_vuln"] = self._test_runs(
                "upstream_test_on_vuln", run, vo, want_pass=False, env=env)
            if c["fix_applies"]:
                fo = self.trees.fresh("fix_oracle")
                if _apply(fix, fo, allow)[0]:
                    c["upstream_test_passes_on_fix"] = self._test_runs(
                        "upstream_test_on_fix", run, fo, want_pass=True, env=env)

        # 4. agent test against the hidden upstream fix / a fixed release
        ref = self.hidden / "reference" / "fix.patch"
        if ref.is_file() and c["test_applies"]:
            rt = self.trees.fresh("upstream_fix_test")
            ok_ref, d1 = _apply(ref.read_text(encoding="utf-8", errors="replace"), rt)
            ok_t, d2 = _apply(test, rt) if ok_ref else (False, "")
            if ok_ref and ok_t:
                c["agent_test_passes_on_upstream_fix"] = self._test_runs(
                    "agent_test_on_upstream_fix", cmd, rt, want_pass=True)
            else:
                self._step("agent_test_on_upstream_fix", None,
                           f"could not apply (ref: {d1}; test: {d2})")
        rel = self.hidden / "fixed_release"
        if rel.is_dir() and c["test_applies"]:
            tr = self.trees.fresh("fixed_release_test", base=rel)
            ok, d = _apply(test, tr)
            if ok:
                c["agent_test_passes_on_fixed_release"] = self._test_runs(
                    "agent_test_on_fixed_release", cmd, tr, want_pass=True)
            else:
                self._step("agent_test_on_fixed_release", None, f"could not apply: {d}")
        self.trees.done()
        return self._result(sub)

    def _tier(self) -> str:
        c = self.checks
        base = (c["fix_applies"] and c["test_applies"]
                and c["candidate_build_passed"] is not False
                and c["agent_test_fails_on_vuln"] is True
                and c["agent_test_passes_on_fix"] is True
                and c["existing_tests_passed"] is not False)
        if not base:
            return "rejected"
        if c["upstream_test_fails_on_vuln"] and c["upstream_test_passes_on_fix"]:
            return "T1"
        if c["agent_test_passes_on_upstream_fix"]:
            return "T2"
        if c["agent_test_passes_on_fixed_release"]:
            return "T3"
        return "T4"

    def _result(self, sub: dict[str, Any] | None) -> dict[str, Any]:
        c = self.checks
        tier = self._tier() if sub else "rejected"
        for k in ("agent_test_fails_on_vuln", "agent_test_passes_on_fix",
                  "existing_tests_passed", "fix_applies", "test_applies"):
            if sub and c[k] is False:
                self.reasons.append(f"{k} = false")
        final = {"T1": "PATCH_VERIFIED", "T2": "PATCH_VERIFIED", "T3": "PATCH_VERIFIED",
                 "T4": "MANUAL_REVIEW"}.get(tier, "FAILED")
        report = _find_report(self.run_dir)
        rep_eval = evaluate_report(report, self.baseline).to_dict() if report else None
        dims = {
            "patch_format_valid": c["fix_applies"],
            "candidate_build_passed": c["candidate_build_passed"],
            "baseline_reproduced": c["agent_test_fails_on_vuln"],
            "regression_test_passed": c["agent_test_passes_on_fix"],
            "existing_tests_passed": c["existing_tests_passed"],
            "infrastructure_failure": False,
        }
        return {
            "schema_version": "1",
            "verifier_version": VERIFIER_VERSION,
            "task_id": self.task.task_id,
            "cve_id": self.task.raw.get("cve_id"),
            "tier": tier,
            "final_status": final,
            "capabilities": {k: v for k, v in {**dims, **c}.items() if isinstance(v, bool)},
            "checks": c,
            "dimensions": dims,
            "steps": self.steps,
            "failure_reasons": self.reasons,
            "submission": None if sub is None else {
                "test_files": sub.get("test_files"), "test_command": sub.get("test_command"),
                "fix_files": sub.get("fix_files"),
                "fix_lines": sub["fix_patch"].count("\n"),
                "test_lines": sub["test_patch"].count("\n"),
            },
            "report": rep_eval,
        }


def verify(*, run_dir: Path, baseline: Path, hidden: Path,
           work_root: Path | None = None, repeats: int = 2) -> dict[str, Any]:
    tmp = None
    if work_root is None:
        tmp = tempfile.mkdtemp(prefix="cvepatch-verify-")
        work_root = Path(tmp)
    try:
        return Verifier(run_dir=run_dir, baseline=baseline, hidden=hidden,
                        work_root=work_root, repeats=repeats).run()
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="cvepatch tier verifier")
    ap.add_argument("--run", default="/run")
    ap.add_argument("--baseline", default="/opt/defensive/baseline")
    ap.add_argument("--hidden", default="/opt/hidden")
    ap.add_argument("--work-root", default=None)
    ap.add_argument("--repeats", type=int, default=2)
    a = ap.parse_args(argv)
    try:
        out = verify(run_dir=Path(a.run), baseline=Path(a.baseline), hidden=Path(a.hidden),
                     work_root=Path(a.work_root) if a.work_root else None, repeats=a.repeats)
    except Exception as exc:  # noqa: BLE001 - always emit a scorable result
        out = {"schema_version": "1", "verifier_version": VERIFIER_VERSION,
               "tier": "rejected", "final_status": "FAILED",
               "capabilities": {"infrastructure_failure": True},
               "dimensions": {"infrastructure_failure": True}, "checks": {},
               "steps": [], "failure_reasons": [f"verifier crashed: {type(exc).__name__}: {exc}"]}
    sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
