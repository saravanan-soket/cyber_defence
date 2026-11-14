"""Reproducibility manifest emitter.

Captures, per task, the facts the spec §7 requires to re-materialize the env:
source revisions, toolchain, dependency versions, build flags, regression
command, image digest + build logs, source + patch hashes, and the exact
validation commands. Emitted as JSON alongside the env.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.ingestion.provenance import sha256_bytes, utc_now_iso


@dataclass
class ReproManifest:
    task_id: str
    build_mode: str                               # 'dev' | 'reproducible'
    vulnerable_commit: str
    fixed_commit: str | None = None
    toolchain: dict[str, Any] = field(default_factory=dict)
    dependency_versions: dict[str, str] = field(default_factory=dict)
    build_flags: list[str] = field(default_factory=list)
    regression_command: list[str] = field(default_factory=list)
    existing_test_command: list[str] = field(default_factory=list)
    base_image_digest: str | None = None
    image_ref: str | None = None
    image_digest: str | None = None
    build_log_path: str | None = None
    source_sha256: dict[str, str] = field(default_factory=dict)  # rel_path -> sha
    patch_sha256: str | None = None
    validation_commands: dict[str, list[str]] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def write(self, out_path: Path) -> Path:
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return out_path


def hash_source_tree(root: Path, *, max_files: int = 5000) -> dict[str, str]:
    """Return {relative_path: sha256} for every file under `root` (sorted)."""
    root = Path(root)
    out: dict[str, str] = {}
    files = sorted(p for p in root.rglob("*") if p.is_file())
    for p in files[:max_files]:
        try:
            out[str(p.relative_to(root))] = sha256_bytes(p.read_bytes())
        except OSError:
            continue
    return out
