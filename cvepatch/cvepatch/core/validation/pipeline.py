"""The trusted defensive validation pipeline (steps A-G).

Pure Python, no Docker and no LLM. Runs identically on the host (fast
unit/integration tests against a local fixture checkout) and inside the
task container as the `cli_oneshot` grader.

Contract:

    result = validate(task, baseline_src, patch_text, work_root)

`baseline_src` is the TRUSTED vulnerable source tree (read-only reference;
the pipeline copies it, never mutates it). `patch_text` is the agent's
unified-diff submission. The pipeline returns a `ValidationResult` whose
`.to_dict()` validates against validation_result.schema.json.

Guarantees enforced here (see docs/ARCHITECTURE.md §6):
  * A build succeeding never sets baseline_reproduced / regression_test_passed.
  * If the baseline does NOT reproduce the defect under the oracle, the
    verdict is INCONCLUSIVE / MANUAL_REVIEW, never "fixed".
  * PATCH_VERIFIED requires the strategy's required trusted checks to pass
    AND (when required) patch provenance to be established.
  * No LLM output participates in the verdict.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.manifest import DefensiveTask
from cvepatch.core.oracle.base import (
    CommandResult,
    ResourceLimits,
    run_command,
)
from cvepatch.core.oracle.regression_oracle import RegressionOracle
from cvepatch.core.validation.patch_validator import (
    PatchValidationError,
    apply_patch_to_tree,
    validate_patch,
)

GRADER_VERSION = "defensive-grader-1.0.0"

# The ordered defensive dimensions. All start as None (unknown / not evaluated).
_DIMENSIONS: tuple[str, ...] = (
    "detection_correct",
    "root_cause_supported",
    "patch_format_valid",
    "candidate_build_passed",
    "baseline_reproduced",
    "regression_test_passed",
    "existing_tests_passed",
    "security_checks_passed",
    "patch_provenance_verified",
    "validation_reproducible",
    "false_positive",
    "infrastructure_failure",
)


@dataclass
class StepRecord:
    step: str
    name: str
    status: str                       # pass|fail|skip|error|unverified
    detail: str | None = None
    exit_code: int | None = None
    duration_s: float | None = None
    timed_out: bool | None = None
    output_excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "exit_code": self.exit_code,
            "duration_s": self.duration_s,
            "timed_out": self.timed_out,
            "output_excerpt": self.output_excerpt,
        }


@dataclass
class ValidationResult:
    task_id: str
    final_status: str
    dimensions: dict[str, bool | None]
    steps: list[StepRecord]
    failure_reasons: list[str]
    patch_base_revision: str | None = None
    patch_sha256: str | None = None
    evidence: list[dict[str, Any]] = field(default_factory=list)
    report: dict[str, Any] | None = None
    grader_version: str = GRADER_VERSION

    def capabilities(self) -> dict[str, bool]:
        """Flat {flag: bool} projection (only non-null dims) for the runner."""
        return {k: bool(v) for k, v in self.dimensions.items() if v is not None}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1",
            "task_id": self.task_id,
            "grader_version": self.grader_version,
            "final_status": self.final_status,
            "dimensions": dict(self.dimensions),
            "capabilities": self.capabilities(),
            "steps": [s.to_dict() for s in self.steps],
            "failure_reasons": list(self.failure_reasons),
            "patch_base_revision": self.patch_base_revision,
            "patch_sha256": self.patch_sha256,
            "evidence": list(self.evidence),
            "report": self.report,
        }


def _copy_checkout(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, symlinks=True)


class CheckoutError(RuntimeError):
    """The trusted tree cannot be used as a checkout (not a repo / dirty)."""


def _git(src: Path, *args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(src), *args], capture_output=True,
                          text=True, timeout=timeout)


def git_tree_is_clean(src: Path) -> bool:
    """True when `src` is a git work tree with no tracked edits or stray
    untracked files (ignored files such as build outputs are allowed)."""
    r = _git(src, "status", "--porcelain")
    return r.returncode == 0 and r.stdout.strip() == ""


def git_reset_tree(src: Path) -> None:
    """Restore tracked files and drop untracked, NON-ignored files. Ignored
    build outputs (e.g. V8's out/) are kept so the next build is incremental."""
    _git(src, "checkout", "--", ".")
    _git(src, "clean", "-fd")


class _Checkouts:
    """Where the baseline and candidate trees live.

    copy (default): each checkout is a fresh copy of the trusted tree under
        work_root. Simple and isolated; fine for small trees.
    git: the trusted tree itself is used in place — baseline is built and
        tested as-is, then the patch is applied, rebuilt incrementally and
        tested, and the tree is always reset afterwards. For large trees
        (V8 is ~28 GB with build outputs) where copying is impractical. Safe
        because the grader runs in a disposable container.
    """

    def __init__(self, mode: str, src: Path, work_root: Path) -> None:
        self.mode, self.src, self.work_root = mode, src, work_root
        self._checked = False

    def _verify_git(self) -> None:
        if self._checked:
            return
        if _git(self.src, "rev-parse", "--is-inside-work-tree").returncode != 0:
            raise CheckoutError(f"checkout_mode=git but {self.src} is not a git work tree")
        if not git_tree_is_clean(self.src):
            raise CheckoutError(f"checkout_mode=git but {self.src} has local changes")
        self._checked = True

    def baseline(self) -> Path:
        if self.mode == "git":
            self._verify_git()
            return self.src
        dst = self.work_root / "baseline"
        _copy_checkout(self.src, dst)
        return dst

    def candidate(self) -> Path:
        if self.mode == "git":
            self._verify_git()  # no-op if baseline already verified; tree untouched since
            return self.src
        dst = self.work_root / "candidate"
        _copy_checkout(self.src, dst)
        return dst

    def reset(self) -> None:
        if self.mode == "git" and self._checked:
            git_reset_tree(self.src)


def _build(task: DefensiveTask, checkout: Path, limits: ResourceLimits) -> CommandResult:
    bi = task.build_instructions
    cwd = checkout / bi["workdir"] if bi.get("workdir") else checkout
    return run_command(
        bi["command"],
        cwd=cwd,
        timeout_s=int(bi.get("timeout_s", 600)),
        limits=limits,
    )


def _regression_oracle(task: DefensiveTask, limits: ResourceLimits) -> RegressionOracle | None:
    spec = task.regression_test_command
    if spec is None:
        return None
    oracle = RegressionOracle.from_command_spec(spec, limits=limits)
    # Common sanitizer markers folded into the invariant check so a process
    # that exits 0 but printed an ASan report still counts as a violation.
    return oracle


def validate(
    task: DefensiveTask,
    baseline_src: Path,
    patch_text: str,
    *,
    work_root: Path | None = None,
    base_revision: str | None = None,
    report: dict[str, Any] | None = None,
) -> ValidationResult:
    """Run the full A-G pipeline and return a deterministic verdict."""
    baseline_src = Path(baseline_src)
    limits = ResourceLimits.from_task(task.resource_limits)
    dims: dict[str, bool | None] = dict.fromkeys(_DIMENSIONS, None)
    steps: list[StepRecord] = []
    failures: list[str] = []
    evidence: list[dict[str, Any]] = []

    cleanup_root = None
    if work_root is None:
        cleanup_root = tempfile.mkdtemp(prefix="defensive-validate-")
        work_root = Path(cleanup_root)
    work_root = Path(work_root)
    work_root.mkdir(parents=True, exist_ok=True)

    patch_sha: str | None = None
    checkouts = _Checkouts(task.checkout_mode, baseline_src, work_root)

    try:
        # ---------- Step A: validate submission ----------
        require_patch = True
        patch_info = None
        try:
            patch_info = validate_patch(
                patch_text,
                allowlist=task.patched_files_allowlist,
                require_nonempty=require_patch,
            )
            patch_sha = patch_info.sha256
            if patch_info.disallowed:
                dims["patch_format_valid"] = False
                failures.append(
                    f"patch touches files outside the allowlist: "
                    f"{list(patch_info.disallowed)}"
                )
                steps.append(StepRecord(
                    "A", "validate_submission", "fail",
                    detail=f"disallowed paths: {list(patch_info.disallowed)}",
                ))
            else:
                dims["patch_format_valid"] = True
                steps.append(StepRecord(
                    "A", "validate_submission", "pass",
                    detail=f"{patch_info.num_hunks} hunk(s), paths={list(patch_info.paths)}",
                ))
                evidence.append({"kind": "patch_sha256", "ref": patch_info.sha256,
                                 "sha256": patch_info.sha256})
        except PatchValidationError as exc:
            dims["patch_format_valid"] = False
            failures.append(f"patch validation failed: {exc}")
            steps.append(StepRecord("A", "validate_submission", "fail", detail=str(exc)))

        # ---------- Step B: baseline reproduction ----------
        oracle = _regression_oracle(task, limits)
        baseline_reproduced: bool | None = None
        if oracle is None:
            steps.append(StepRecord(
                "B", "baseline_reproduction", "unverified",
                detail="no regression oracle (manual_only / null command)",
            ))
        else:
            try:
                base_co = checkouts.baseline()
                b_build = _build(task, base_co, limits)
                if b_build.exit_code != 0 and not _build_optional(task):
                    steps.append(StepRecord(
                        "B", "baseline_build", "error",
                        detail="baseline failed to build",
                        exit_code=b_build.exit_code,
                        output_excerpt=b_build.combined_excerpt,
                        timed_out=b_build.timed_out,
                    ))
                    dims["infrastructure_failure"] = True
                    failures.append("baseline build failed; cannot confirm reproduction")
                else:
                    outcome = oracle.evaluate(base_co)
                    cr = outcome.command_result
                    # For a reproducible vuln, expected_baseline_result ==
                    # 'regression_fail' => the oracle must FAIL (invariant
                    # violated) on the unpatched baseline.
                    if task.expected_baseline_result == "regression_fail":
                        baseline_reproduced = (outcome.passed is False)
                    elif task.expected_baseline_result == "regression_pass":
                        baseline_reproduced = (outcome.passed is True)
                    else:
                        baseline_reproduced = None
                    dims["baseline_reproduced"] = baseline_reproduced
                    steps.append(StepRecord(
                        "B", "baseline_reproduction",
                        "pass" if baseline_reproduced else
                        ("unverified" if baseline_reproduced is None else "fail"),
                        detail=(
                            f"expected={task.expected_baseline_result}; "
                            f"oracle_passed={outcome.passed}; {outcome.detail}"
                        ),
                        exit_code=cr.exit_code if cr else None,
                        duration_s=cr.duration_s if cr else None,
                        timed_out=cr.timed_out if cr else None,
                        output_excerpt=cr.combined_excerpt if cr else None,
                    ))
                    if baseline_reproduced is False:
                        failures.append(
                            "baseline did not exhibit the expected failure; "
                            "oracle unreliable for this task"
                        )
            except Exception as exc:  # noqa: BLE001
                dims["infrastructure_failure"] = True
                steps.append(StepRecord(
                    "B", "baseline_reproduction", "error", detail=f"{type(exc).__name__}: {exc}",
                ))
                failures.append(f"baseline reproduction errored: {exc}")

        # Candidate steps only run if the patch is format-valid.
        cand_co: Path | None = None
        built_ok = False
        if dims["patch_format_valid"] and patch_info is not None:
            try:
                cand_co = checkouts.candidate()
                applied = apply_patch_to_tree(patch_info, cand_co)
                if not applied.ok:
                    dims["candidate_build_passed"] = False
                    failures.append(f"patch did not apply cleanly: {applied.detail}")
                    steps.append(StepRecord(
                        "C", "candidate_apply", "fail",
                        detail=f"{applied.tool}: {applied.detail}",
                    ))
                else:
                    steps.append(StepRecord(
                        "C", "candidate_apply", "pass",
                        detail=f"applied via {applied.tool}",
                    ))
                    # ---------- Step C: candidate build ----------
                    c_build = _build(task, cand_co, limits)
                    built_ok = (c_build.exit_code == 0)
                    dims["candidate_build_passed"] = built_ok
                    steps.append(StepRecord(
                        "C", "candidate_build",
                        "pass" if built_ok else "fail",
                        detail="candidate build",
                        exit_code=c_build.exit_code,
                        duration_s=c_build.duration_s,
                        timed_out=c_build.timed_out,
                        output_excerpt=c_build.combined_excerpt,
                    ))
                    if not built_ok:
                        failures.append("candidate build failed")
            except Exception as exc:  # noqa: BLE001
                dims["infrastructure_failure"] = True
                steps.append(StepRecord("C", "candidate_build", "error",
                                        detail=f"{type(exc).__name__}: {exc}"))
                failures.append(f"candidate build errored: {exc}")
        else:
            steps.append(StepRecord("C", "candidate_build", "skip",
                                    detail="skipped: patch not format-valid"))

        # ---------- Step D: regression verification (candidate) ----------
        if oracle is None:
            steps.append(StepRecord("D", "regression_verification", "unverified",
                                    detail="no regression oracle"))
        elif built_ok:
            outcome = oracle.evaluate(cand_co)
            cr = outcome.command_result
            reg_pass = (outcome.passed is True)
            dims["regression_test_passed"] = reg_pass
            steps.append(StepRecord(
                "D", "regression_verification",
                "pass" if reg_pass else ("unverified" if outcome.passed is None else "fail"),
                detail=outcome.detail,
                exit_code=cr.exit_code if cr else None,
                duration_s=cr.duration_s if cr else None,
                timed_out=cr.timed_out if cr else None,
                output_excerpt=cr.combined_excerpt if cr else None,
            ))
            if not reg_pass:
                failures.append("regression test did not pass on the candidate")
        else:
            steps.append(StepRecord("D", "regression_verification", "skip",
                                    detail="skipped: candidate did not build"))

        # ---------- Step E: existing test suite ----------
        if task.existing_test_command is None:
            steps.append(StepRecord("E", "existing_tests", "unverified",
                                    detail="no existing-test suite declared"))
        elif built_ok:
            spec = task.existing_test_command
            cwd = cand_co / spec["workdir"] if spec.get("workdir") else cand_co
            cr = run_command(spec["command"], cwd=cwd,
                             timeout_s=int(spec.get("timeout_s", 300)), limits=limits)
            ex_pass = (cr.exit_code == 0 and not cr.timed_out)
            dims["existing_tests_passed"] = ex_pass
            steps.append(StepRecord(
                "E", "existing_tests", "pass" if ex_pass else "fail",
                detail="pre-existing functional suite",
                exit_code=cr.exit_code, duration_s=cr.duration_s,
                timed_out=cr.timed_out, output_excerpt=cr.combined_excerpt,
            ))
            if not ex_pass:
                failures.append("existing tests failed (possible regression or "
                                "test-suppression patch)")
        else:
            steps.append(StepRecord("E", "existing_tests", "skip",
                                    detail="skipped: candidate did not build"))

        # ---------- Step F: independent security checks ----------
        if not task.security_checks:
            steps.append(StepRecord("F", "security_checks", "unverified",
                                    detail="no extra security checks declared"))
        elif built_ok:
            all_pass = True
            any_run = False
            for i, spec in enumerate(task.security_checks):
                any_run = True
                cwd = cand_co / spec["workdir"] if spec.get("workdir") else cand_co
                cr = run_command(spec["command"], cwd=cwd,
                                 timeout_s=int(spec.get("timeout_s", 300)), limits=limits)
                ok = (cr.exit_code == 0 and not cr.timed_out)
                all_pass = all_pass and ok
                steps.append(StepRecord(
                    "F", f"security_check:{spec.get('name', i)}",
                    "pass" if ok else "fail",
                    detail=f"kind={spec.get('kind', 'regression')}",
                    exit_code=cr.exit_code, duration_s=cr.duration_s,
                    timed_out=cr.timed_out, output_excerpt=cr.combined_excerpt,
                ))
            if any_run:
                dims["security_checks_passed"] = all_pass
                if not all_pass:
                    failures.append("one or more independent security checks failed")
        else:
            steps.append(StepRecord("F", "security_checks", "skip",
                                    detail="skipped: candidate did not build"))

        # ---------- provenance ----------
        prov = task.patch_provenance
        if not task.provenance_required:
            dims["patch_provenance_verified"] = None
        else:
            dims["patch_provenance_verified"] = (prov.get("status") == "verified")
            if dims["patch_provenance_verified"] is False:
                failures.append(
                    f"patch provenance not verified (status="
                    f"{prov.get('status')!r})"
                )

        # validation_reproducible: the pipeline itself ran deterministically
        # end-to-end without an infrastructure failure.
        dims["validation_reproducible"] = not bool(dims["infrastructure_failure"])

        # ---------- detection / false_positive ----------
        # detection_correct is a mechanical signal: the candidate changed the
        # behavior from vulnerable->safe under the trusted oracle. It is True
        # only when baseline reproduced AND the candidate regression passed.
        if dims["baseline_reproduced"] and dims["regression_test_passed"]:
            dims["detection_correct"] = True
        elif dims["baseline_reproduced"] is True and dims["regression_test_passed"] is False:
            dims["detection_correct"] = False

        # false_positive: a non-empty, well-formed patch that does NOT actually
        # fix the bug (regression still fails) or that breaks existing tests.
        if dims["patch_format_valid"]:
            if (dims["regression_test_passed"] is False
                    or dims["existing_tests_passed"] is False):
                dims["false_positive"] = True
            elif dims["regression_test_passed"] is True and dims["existing_tests_passed"] in (True, None):
                dims["false_positive"] = False

        # ---------- report (kept separate from verdict) ----------
        if report is not None:
            dims["root_cause_supported"] = bool(report.get("passed"))

        # ---------- Step G: final verdict ----------
        final_status = _derive_status(task, dims)
        steps.append(StepRecord("G", "final_verdict", "pass",
                                detail=f"final_status={final_status}"))

        return ValidationResult(
            task_id=task.task_id,
            final_status=final_status,
            dimensions=dims,
            steps=steps,
            failure_reasons=failures,
            patch_base_revision=base_revision,
            patch_sha256=patch_sha,
            evidence=evidence,
            report=report,
        )
    finally:
        checkouts.reset()
        if cleanup_root is not None:
            shutil.rmtree(cleanup_root, ignore_errors=True)


def _build_optional(task: DefensiveTask) -> bool:
    """Some tasks (e.g. pure-script fixtures) have a no-op build; treat a
    non-zero baseline build as fatal unless metadata opts out."""
    return bool(task.metadata.get("build_optional", False))


def _derive_status(task: DefensiveTask, dims: dict[str, bool | None]) -> str:
    """Map the dimension bitmap to a single lifecycle verdict.

    PATCH_VERIFIED requires:
      * patch_format_valid
      * baseline_reproduced (the oracle confirmed the defect exists)
      * candidate_build_passed
      * regression_test_passed
      * existing_tests_passed where the strategy requires it
      * security_checks_passed where declared
      * patch_provenance_verified where required
    When the oracle is unreliable (no baseline reproduction), the verdict is
    capped at INCONCLUSIVE / MANUAL_REVIEW regardless of other signals.
    """
    if dims.get("infrastructure_failure"):
        return "FAILED"

    if not task.has_reliable_oracle:
        return "MANUAL_REVIEW"

    # Baseline must reproduce for any claim about a fix to be meaningful.
    if dims.get("baseline_reproduced") is None:
        return "INCONCLUSIVE"
    if dims.get("baseline_reproduced") is False:
        return "INCONCLUSIVE"

    # Baseline reproduced => at least REPRODUCIBLE.
    required_ok = (
        dims.get("patch_format_valid") is True
        and dims.get("candidate_build_passed") is True
        and dims.get("regression_test_passed") is True
    )
    if task.requires_existing_tests:
        required_ok = required_ok and (dims.get("existing_tests_passed") is True)
    # If an existing suite ran and failed, never verify (test-suppression guard).
    if dims.get("existing_tests_passed") is False:
        required_ok = False
    # Declared security checks must pass if they ran.
    if dims.get("security_checks_passed") is False:
        required_ok = False
    if task.provenance_required and dims.get("patch_provenance_verified") is not True:
        required_ok = False

    if required_ok:
        return "PATCH_VERIFIED"
    if dims.get("candidate_build_passed") is True:
        return "REPRODUCIBLE"  # reproduced + built, but patch not verified
    return "REPRODUCIBLE"
