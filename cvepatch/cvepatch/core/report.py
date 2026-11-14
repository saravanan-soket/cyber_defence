"""Root-cause report: schema validation + mechanical cross-checks.

The defensive agent may submit a structured root-cause report. This module
validates its schema and checks the *mechanically verifiable* claims against
the trusted source tree:

  * `affected_file` exists in the source tree;
  * `affected_line_range` is within that file's length;
  * any `commit_references` resolve in the repo (when it is a git checkout).

It deliberately does NOT award correctness for using the right CWE label or
echoing the CVE description — semantic evaluation is out of scope here and is
kept entirely separate from the deterministic patch-verification verdict
(the report never influences PATCH_VERIFIED).
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.schemas import iter_errors
from cvepatch.core.validation.patch_validator import _is_safe_relative


@dataclass
class ReportCheck:
    name: str
    passed: bool
    detail: str


@dataclass
class ReportEvaluation:
    schema_valid: bool
    passed: bool                       # all MECHANICAL checks passed
    checks: list[ReportCheck] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_valid": self.schema_valid,
            "passed": self.passed,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail}
                       for c in self.checks],
            "schema_errors": list(self.schema_errors),
        }


def evaluate_report(report: dict[str, Any], source_dir: Path) -> ReportEvaluation:
    """Validate the report schema + run mechanical cross-checks vs. `source_dir`."""
    source_dir = Path(source_dir)
    errors = iter_errors("root_cause_report", report)
    if errors:
        return ReportEvaluation(schema_valid=False, passed=False, schema_errors=errors)

    checks: list[ReportCheck] = []

    # affected_file must be a safe relative path that exists.
    rel = report["affected_file"]
    if not _is_safe_relative(rel):
        checks.append(ReportCheck("affected_file_safe", False,
                                  f"unsafe/absolute path: {rel!r}"))
    else:
        target = source_dir / rel
        exists = target.is_file()
        checks.append(ReportCheck("affected_file_exists", exists,
                                  f"{rel} {'found' if exists else 'MISSING'}"))
        # line range within file length
        start, end = report["affected_line_range"]
        if exists:
            n_lines = sum(1 for _ in target.open("r", encoding="utf-8", errors="replace"))
            ok = 1 <= start <= end <= n_lines
            checks.append(ReportCheck(
                "line_range_valid", ok,
                f"[{start},{end}] vs {n_lines} lines",
            ))
        else:
            checks.append(ReportCheck("line_range_valid", False,
                                      "cannot check range: file missing"))

    # commit references resolve (best-effort; only when source_dir is a repo).
    refs = report.get("commit_references") or []
    if refs:
        git = shutil.which("git")
        is_repo = (source_dir / ".git").exists()
        for ref in refs:
            if not git or not is_repo:
                checks.append(ReportCheck(f"commit:{ref}", False,
                                          "not a git checkout; cannot verify"))
                continue
            try:
                r = subprocess.run(
                    [git, "-C", str(source_dir), "cat-file", "-e", f"{ref}^{{commit}}"],
                    capture_output=True, timeout=15,
                )
                ok = r.returncode == 0
            except (OSError, subprocess.SubprocessError):
                ok = False
            checks.append(ReportCheck(f"commit:{ref}", ok,
                                      "resolves" if ok else "does not resolve"))

    passed = all(c.passed for c in checks) and bool(checks)
    return ReportEvaluation(schema_valid=True, passed=passed, checks=checks)
