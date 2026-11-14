"""Oracle interface + a sandboxed command runner shared by oracles/builders.

An *oracle* decides, from executing something against a source tree, whether
a security invariant holds. The regression oracle is the primary one; the
differential and static-analysis oracles are declared here as the extension
surface and implemented incrementally.

`run_command` is the single chokepoint for spawning subprocesses during
validation. It applies a wall-clock timeout, optional POSIX resource limits
(address space, CPU seconds, process count), output truncation, and places
the child in its own process group so a timeout kills the whole tree.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

MAX_CAPTURE_BYTES = 64 * 1024


@dataclass(frozen=True)
class ResourceLimits:
    """POSIX rlimits applied to a validation subprocess (best-effort)."""

    memory_mb: int | None = None
    cpu_s: int | None = None
    pids: int | None = None
    wallclock_s: int | None = None

    @classmethod
    def from_task(cls, d: dict | None) -> ResourceLimits:
        d = d or {}
        return cls(
            memory_mb=d.get("memory_mb"),
            cpu_s=int(d["cpu"]) if d.get("cpu") else None,
            pids=d.get("pids"),
            wallclock_s=d.get("wallclock_s"),
        )


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool

    @property
    def combined_excerpt(self) -> str:
        out = (self.stdout or "") + ("\n" + self.stderr if self.stderr else "")
        return out[-4000:]


def _preexec(limits: ResourceLimits):
    """Return a preexec_fn applying rlimits + a fresh process group, or None."""

    def _apply() -> None:
        # New process group so timeout kill reaches the whole tree.
        os.setsid()
        try:
            import resource

            if limits.memory_mb:
                nbytes = limits.memory_mb * 1024 * 1024
                resource.setrlimit(resource.RLIMIT_AS, (nbytes, nbytes))
            if limits.cpu_s:
                resource.setrlimit(resource.RLIMIT_CPU, (limits.cpu_s, limits.cpu_s))
            # NOTE: process-count limiting is intentionally NOT done via
            # RLIMIT_NPROC here. RLIMIT_NPROC is per-UID and counts every
            # process the user already owns, so on a shared host (or a
            # container sharing a UID with other work) setting it instantly
            # blocks fork() for unrelated builds. The process-count cap
            # belongs to the container's cgroup `--pids-limit`, applied by
            # the env image / docker run flags. `limits.pids` is still
            # recorded on the task for the container layer to consume.
        except Exception:
            # rlimits are best-effort; never fail the spawn because a limit
            # couldn't be set (container may already cap these).
            pass

    return _apply


def run_command(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: Path | str,
    timeout_s: int,
    env: dict[str, str] | None = None,
    limits: ResourceLimits | None = None,
) -> CommandResult:
    """Run `argv` in `cwd` with a hard timeout + optional rlimits.

    Never raises on non-zero exit or timeout — the caller inspects
    `exit_code` / `timed_out`. Output is captured and truncated.
    """
    limits = limits or ResourceLimits()
    argv = list(argv)
    start = time.monotonic()
    run_env = dict(os.environ)
    if env:
        run_env.update(env)

    try:
        proc = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=run_env,
            preexec_fn=_preexec(limits),
            text=True,
        )
    except (OSError, ValueError) as exc:
        return CommandResult(
            argv=tuple(argv), exit_code=None, stdout="",
            stderr=f"spawn failed: {exc}", duration_s=0.0, timed_out=False,
        )

    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        # Kill the whole process group.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""

    return CommandResult(
        argv=tuple(argv),
        exit_code=proc.returncode,
        stdout=(stdout or "")[:MAX_CAPTURE_BYTES],
        stderr=(stderr or "")[:MAX_CAPTURE_BYTES],
        duration_s=round(time.monotonic() - start, 3),
        timed_out=timed_out,
    )


@dataclass
class OracleOutcome:
    """What an oracle concluded about one execution."""

    passed: bool | None          # None = could not conclude (infra/oracle failure)
    detail: str
    command_result: CommandResult | None = None
    evidence: dict = field(default_factory=dict)


class Oracle(ABC):
    """Decides whether the security invariant holds for a given checkout."""

    name: str = "oracle"

    @abstractmethod
    def evaluate(self, checkout_dir: Path) -> OracleOutcome:  # pragma: no cover
        ...
