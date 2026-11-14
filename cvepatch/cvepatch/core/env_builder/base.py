"""Environment-builder interface for defensive tasks (task spec §7).

An EnvironmentBuilder turns a vulnerability + its source revisions into a
reproducible task environment. The interface is explicit about each lifecycle
step so a new ecosystem (V8, curl, …) implements the same contract. The V8
builder REUSES bench-v8's existing env-builder rather than replacing it.

A builder NEVER advances a task past BUILDABLE on its own — reproduction and
patch verification are the trusted validator's job (lifecycle invariant).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class PreparedSource:
    """A source tree prepared at a specific revision."""

    path: Path
    revision: str
    kind: str                       # 'baseline' | 'candidate'
    pinned_deps: dict[str, str] = field(default_factory=dict)


@dataclass
class BuildMode:
    DEV = "dev"
    REPRODUCIBLE = "reproducible"


@dataclass
class BuildResult:
    ok: bool
    mode: str
    image_ref: str | None = None
    image_digest: str | None = None
    build_log_path: str | None = None
    toolchain: dict[str, Any] = field(default_factory=dict)
    detail: str = ""


class EnvironmentBuilder(ABC):
    """The explicit lifecycle a defensive env goes through."""

    #: 'dev' (fast local) or 'reproducible' (pinned toolchain + recorded digests)
    mode: str = BuildMode.DEV

    @abstractmethod
    def resolve_revisions(self) -> dict[str, str]:
        """Return {'vulnerable': <rev>, 'fixed': <rev|None>} resolved + verified."""

    @abstractmethod
    def prepare_source(self, revision: str, *, kind: str) -> PreparedSource:
        """Check out / materialize the source tree at `revision`."""

    @abstractmethod
    def pin_dependencies(self, src: PreparedSource) -> dict[str, str]:
        """Pin and record dependency versions for reproducibility."""

    @abstractmethod
    def generate_task_manifest(self, out_path: Path) -> Path:
        """Emit the defensive task manifest (validated) for this env."""

    @abstractmethod
    def prepare_baseline(self) -> PreparedSource:
        """Prepare the vulnerable baseline workspace."""

    @abstractmethod
    def prepare_candidate_workspace(self, baseline: PreparedSource) -> PreparedSource:
        """Prepare the writable candidate workspace (a copy of the baseline)."""

    @abstractmethod
    def build(self, src: PreparedSource) -> BuildResult:
        """Build the software; record toolchain + logs. NEVER advances past BUILDABLE."""

    @abstractmethod
    def run_baseline_regression(self, baseline: PreparedSource) -> dict[str, Any]:
        """Run the trusted regression test against the vulnerable baseline."""

    @abstractmethod
    def run_patched_regression(self, candidate: PreparedSource) -> dict[str, Any]:
        """Run the trusted regression test against a patched candidate."""

    @abstractmethod
    def export_reproducibility_metadata(self, out_path: Path) -> Path:
        """Write the reproducibility manifest (digests, hashes, commands)."""
