"""Builder for the synthetic fixture env — real, fast, no Docker required.

Materializes the baseline/candidate workspaces from
`testenvs/defensive-fixture/baseline`, builds with the host C compiler, runs
the regression against baseline (expect FAIL) and candidate (expect PASS),
and emits the reproducibility manifest. This is the concrete, executable
reference implementation of the EnvironmentBuilder contract used by the
end-to-end tests.
"""

from __future__ import annotations

import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cvepatch.core import manifest as task_manifest
from cvepatch.core.env_builder.base import (
    BuildMode,
    BuildResult,
    EnvironmentBuilder,
    PreparedSource,
)
from cvepatch.core.env_builder.manifest import ReproManifest, hash_source_tree
from cvepatch.core.oracle.base import ResourceLimits
from cvepatch.core.oracle.regression_oracle import RegressionOracle


class FixtureBuilder(EnvironmentBuilder):
    def __init__(
        self,
        *,
        baseline_src: Path,
        task_path: Path,
        work_root: Path | None = None,
        mode: str = BuildMode.DEV,
    ) -> None:
        self.baseline_src = Path(baseline_src)
        self.task_path = Path(task_path)
        self.task = task_manifest.load(self.task_path)
        self.mode = mode
        self._work_root = Path(work_root) if work_root else Path(
            tempfile.mkdtemp(prefix="fixture-builder-")
        )
        self._work_root.mkdir(parents=True, exist_ok=True)

    def resolve_revisions(self) -> dict[str, str]:
        return {"vulnerable": self.task.vulnerable_commit, "fixed": self.task.fixed_commit}

    def prepare_source(self, revision: str, *, kind: str) -> PreparedSource:
        dst = self._work_root / kind
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(self.baseline_src, dst)
        return PreparedSource(path=dst, revision=revision, kind=kind)

    def pin_dependencies(self, src: PreparedSource) -> dict[str, str]:
        cc = shutil.which("cc") or shutil.which("gcc") or "cc"
        try:
            ver = subprocess.run([cc, "--version"], capture_output=True, text=True,
                                 timeout=15).stdout.splitlines()[:1]
        except (OSError, subprocess.SubprocessError):
            ver = []
        deps = {"cc": ver[0] if ver else cc, "platform": platform.platform()}
        src.pinned_deps.update(deps)
        return deps

    def generate_task_manifest(self, out_path: Path) -> Path:
        # The fixture's manifest is authored; copy it to the requested path.
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(self.task_path, out_path)
        return out_path

    def prepare_baseline(self) -> PreparedSource:
        return self.prepare_source(self.task.vulnerable_commit, kind="baseline")

    def prepare_candidate_workspace(self, baseline: PreparedSource) -> PreparedSource:
        return self.prepare_source(self.task.vulnerable_commit, kind="candidate")

    def _limits(self) -> ResourceLimits:
        return ResourceLimits.from_task(self.task.resource_limits)

    def build(self, src: PreparedSource) -> BuildResult:
        bi = self.task.build_instructions
        cwd = src.path / bi["workdir"] if bi.get("workdir") else src.path
        proc = subprocess.run(bi["command"], cwd=str(cwd), capture_output=True,
                              text=True, timeout=int(bi.get("timeout_s", 120)))
        log = self._work_root / f"build-{src.kind}.log"
        log.write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
        return BuildResult(
            ok=(proc.returncode == 0), mode=self.mode,
            build_log_path=str(log),
            toolchain=src.pinned_deps,
            detail=f"exit={proc.returncode}",
        )

    def _regression(self, src: PreparedSource) -> dict[str, Any]:
        spec = self.task.regression_test_command
        oracle = RegressionOracle.from_command_spec(spec, limits=self._limits())
        outcome = oracle.evaluate(src.path)
        return {"passed": outcome.passed, "detail": outcome.detail,
                "exit_code": outcome.command_result.exit_code if outcome.command_result else None}

    def run_baseline_regression(self, baseline: PreparedSource) -> dict[str, Any]:
        return self._regression(baseline)

    def run_patched_regression(self, candidate: PreparedSource) -> dict[str, Any]:
        return self._regression(candidate)

    def export_reproducibility_metadata(self, out_path: Path) -> Path:
        bi = self.task.build_instructions
        reg = self.task.regression_test_command or {}
        existing = self.task.existing_test_command or {}
        rm = ReproManifest(
            task_id=self.task.task_id,
            build_mode=self.mode,
            vulnerable_commit=self.task.vulnerable_commit,
            fixed_commit=self.task.fixed_commit,
            toolchain={"compiler": shutil.which("cc") or "cc", "platform": platform.platform()},
            build_flags=list(bi.get("command", [])),
            regression_command=list(reg.get("command", [])),
            existing_test_command=list(existing.get("command", [])),
            source_sha256=hash_source_tree(self.baseline_src),
            patch_sha256=self.task.patch_provenance.get("content_sha256"),
            validation_commands={
                "build": list(bi.get("command", [])),
                "regression": list(reg.get("command", [])),
                "existing": list(existing.get("command", [])),
            },
        )
        return rm.write(out_path)
