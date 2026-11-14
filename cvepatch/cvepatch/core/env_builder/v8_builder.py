"""V8 defensive env builder — REUSES bench-v8's env-builder.

The offensive bench-v8 submodule already knows how to materialize a V8 source
tree at a pinned revision, generate build configs (args.*.gn), apply the bug
patch, and produce a standalone Dockerfile (see
benchmarks/bench-v8/env-builder/bootstrap_v8.py). The defensive V8 builder
wraps that machinery rather than reimplementing a generic Dockerfile that
could not reproduce the relevant source revision.

Because a full V8 image is ~65-70 GB and requires the V8 build toolchain + a
running Docker daemon, this builder does NOT execute the heavy build during
import or in the standard test suite. It:

  * locates the bench-v8 env-builder and validates the submodule is present;
  * resolves the vulnerable/fixed revisions from the task manifest;
  * delegates image generation to bootstrap_v8 when asked to build (operator
    step, documented in docs/RUNBOOK.md);
  * emits the defensive task manifest + reproducibility metadata.

Reproduction + patch verification remain the trusted validator's job: a
built V8 image never auto-advances past BUILDABLE.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from cvepatch.core import manifest as task_manifest
from cvepatch.core.env_builder.base import (
    BuildMode,
    BuildResult,
    EnvironmentBuilder,
    PreparedSource,
)
from cvepatch.core.env_builder.manifest import ReproManifest


class V8BuilderUnavailable(RuntimeError):
    """bench-v8 env-builder or Docker toolchain is not available here."""


class V8DefensiveBuilder(EnvironmentBuilder):
    """Thin adapter over bench-v8/env-builder/bootstrap_v8.py."""

    def __init__(
        self,
        *,
        task_path: Path,
        bench_v8_dir: Path,
        work_root: Path,
        mode: str = BuildMode.REPRODUCIBLE,
    ) -> None:
        self.task_path = Path(task_path)
        self.task = task_manifest.load(self.task_path)
        self.bench_v8_dir = Path(bench_v8_dir)
        self.work_root = Path(work_root)
        self.mode = mode

    # -- availability ------------------------------------------------------
    @property
    def bootstrap_path(self) -> Path:
        return self.bench_v8_dir / "env-builder" / "bootstrap_v8.py"

    def ensure_available(self) -> None:
        if not self.bootstrap_path.is_file():
            raise V8BuilderUnavailable(
                f"bench-v8 env-builder not found at {self.bootstrap_path}. "
                f"Initialize the submodule: `git submodule update --init "
                f"benchmarks/bench-v8`."
            )
        if shutil.which("docker") is None:
            raise V8BuilderUnavailable(
                "docker not on PATH; the V8 image build requires a running "
                "Docker daemon and the V8 build toolchain (~65-70 GB image)."
            )

    # -- lifecycle ---------------------------------------------------------
    def resolve_revisions(self) -> dict[str, str]:
        rev = {"vulnerable": self.task.vulnerable_commit, "fixed": self.task.fixed_commit}
        if not rev["vulnerable"]:
            raise ValueError("V8 task manifest is missing vulnerable_commit")
        return rev

    def prepare_source(self, revision: str, *, kind: str) -> PreparedSource:
        # Delegated to bench-v8's bootstrap, which fetches V8 at the pinned
        # crev. Not executed here (heavy); see build().
        return PreparedSource(path=self.work_root / kind, revision=revision, kind=kind)

    def pin_dependencies(self, src: PreparedSource) -> dict[str, str]:
        # bench-v8 pins depot_tools / V8 deps via gclient at the recorded crev.
        return {"source_date_epoch": str(self.task.metadata.get("source_date_epoch", ""))}

    def generate_task_manifest(self, out_path: Path) -> Path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.task_path, out_path)
        return out_path

    def prepare_baseline(self) -> PreparedSource:
        return self.prepare_source(self.task.vulnerable_commit, kind="baseline")

    def prepare_candidate_workspace(self, baseline: PreparedSource) -> PreparedSource:
        return self.prepare_source(self.task.vulnerable_commit, kind="candidate")

    def bootstrap_command(self) -> list[str]:
        """The real bench-v8 bootstrap CLI for this task.

        `bootstrap_v8.py [--force] bug <CVE-…|b/<crbug>> [--pair ID] [--commit SHA]`
        — the bug id is a positional arg of the `bug` subcommand; `--commit`
        pins the fix (last-patch) commit instead of prompting.
        """
        if self.task.cve_id:
            bug_id = self.task.cve_id
            pair = (f"b/{self.task.chromium_issue_id.removeprefix('crbug-')}"
                    if self.task.chromium_issue_id else None)
        elif self.task.chromium_issue_id:
            bug_id = f"b/{self.task.chromium_issue_id.removeprefix('crbug-')}"
            pair = None
        else:
            raise ValueError(
                "V8 task needs cve_id or chromium_issue_id for bench-v8 bootstrap"
            )
        cmd = ["python", str(self.bootstrap_path), "bug", bug_id]
        if pair:
            cmd += ["--pair", pair]
        if self.task.fixed_commit:
            cmd += ["--commit", self.task.fixed_commit]
        return cmd

    def build(self, src: PreparedSource) -> BuildResult:
        """Delegate to bench-v8 bootstrap_v8 (operator step).

        Raises V8BuilderUnavailable when the toolchain/submodule is absent so
        callers fail loudly rather than silently producing a non-reproducing
        image.
        """
        self.ensure_available()
        # Intentionally not shelling out automatically: the V8 build is a
        # long, resource-heavy operator action. The runbook documents the
        # exact bootstrap_v8 invocation. We surface the command instead.
        cmd = self.bootstrap_command()
        return BuildResult(
            ok=False, mode=self.mode,
            detail=("V8 build is an operator step; run: " + " ".join(cmd)
                    + "  (see docs/RUNBOOK.md)"),
            toolchain={"builder": "bench-v8/env-builder/bootstrap_v8.py"},
        )

    def run_baseline_regression(self, baseline: PreparedSource) -> dict[str, Any]:
        return {"passed": None, "detail": "runs inside the built V8 image via the "
                "cli_oneshot grader; not executed on the host"}

    def run_patched_regression(self, candidate: PreparedSource) -> dict[str, Any]:
        return {"passed": None, "detail": "runs inside the built V8 image via the "
                "cli_oneshot grader; not executed on the host"}

    def export_reproducibility_metadata(self, out_path: Path) -> Path:
        reg = self.task.regression_test_command or {}
        rm = ReproManifest(
            task_id=self.task.task_id,
            build_mode=self.mode,
            vulnerable_commit=self.task.vulnerable_commit,
            fixed_commit=self.task.fixed_commit,
            toolchain={"builder": "bench-v8/env-builder/bootstrap_v8.py"},
            regression_command=list(reg.get("command", [])),
            patch_sha256=self.task.patch_provenance.get("content_sha256"),
            validation_commands={"regression": list(reg.get("command", []))},
        )
        return rm.write(out_path)
