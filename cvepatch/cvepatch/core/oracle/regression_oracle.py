"""Regression oracle: run the trusted regression command, interpret the exit.

The regression command encodes the security invariant (per the task
manifest's `regression_test_command.invariant`). Convention:

    exit 0  -> invariant HOLDS   (patched / safe)
    exit !0 -> invariant VIOLATED (vulnerable) OR build/test harness error

This is deliberately simple and deterministic: the invariant is whatever the
command checks (e.g. "runs the PoC under ASan and exits 0 only if no
sanitizer report fired"). The oracle does not parse semantics beyond the
exit code and an optional required/forbidden output substring, so the
contract stays auditable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cvepatch.core.oracle.base import (
    CommandResult,
    Oracle,
    OracleOutcome,
    ResourceLimits,
    run_command,
)


@dataclass
class RegressionOracle(Oracle):
    """Runs a command; PASS iff exit 0 (+ optional output constraints)."""

    command: tuple[str, ...]
    timeout_s: int = 300
    workdir_rel: str | None = None
    limits: ResourceLimits = ResourceLimits()
    forbidden_substrings: tuple[str, ...] = ()   # e.g. ("AddressSanitizer", "runtime error")
    required_substrings: tuple[str, ...] = ()
    name: str = "regression"

    def _interpret(self, res: CommandResult) -> OracleOutcome:
        if res.timed_out:
            return OracleOutcome(
                passed=None,
                detail=f"regression command timed out after {self.timeout_s}s",
                command_result=res,
            )
        if res.exit_code is None:
            return OracleOutcome(
                passed=None,
                detail=f"regression command failed to run: {res.stderr[:200]}",
                command_result=res,
            )
        combined = (res.stdout or "") + "\n" + (res.stderr or "")
        passed = res.exit_code == 0
        reasons: list[str] = []
        if passed:
            for sub in self.forbidden_substrings:
                if sub in combined:
                    passed = False
                    reasons.append(f"forbidden output present: {sub!r}")
            for sub in self.required_substrings:
                if sub not in combined:
                    passed = False
                    reasons.append(f"required output missing: {sub!r}")
        detail = (
            f"exit={res.exit_code}"
            + (f"; {'; '.join(reasons)}" if reasons else "")
        )
        return OracleOutcome(passed=passed, detail=detail, command_result=res)

    def evaluate(self, checkout_dir: Path) -> OracleOutcome:
        cwd = checkout_dir
        if self.workdir_rel:
            cwd = checkout_dir / self.workdir_rel
        res = run_command(
            self.command,
            cwd=cwd,
            timeout_s=self.timeout_s,
            limits=self.limits,
        )
        return self._interpret(res)

    @classmethod
    def from_command_spec(
        cls, spec: dict, limits: ResourceLimits | None = None, *, name: str = "regression"
    ) -> RegressionOracle:
        """Build from a defensive_task `regression_test_command` / `security_checks` entry."""
        return cls(
            command=tuple(spec["command"]),
            timeout_s=int(spec.get("timeout_s", 300)),
            workdir_rel=spec.get("workdir"),
            limits=limits or ResourceLimits(),
            name=name,
        )
