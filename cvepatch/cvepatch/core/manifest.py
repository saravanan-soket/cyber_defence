"""Defensive task manifest: loader + validation + normalized dataclass.

A *defensive task manifest* is the per-task contract carrying the
vulnerability semantics (CVE / commit / class), provenance, build +
regression commands, and the expected baseline/patched results the trusted
grader reads. It is distinct from the runner's per-env
`contract/manifest.py` (which describes the image/env record). A defensive
task ships both.

Canonical form is `schemas/defensive_task.schema.json`. This module loads
YAML or JSON, validates against that schema, then applies cross-field
checks the schema can't express on its own (e.g. a regression validation
strategy must supply a regression command; `manual_only` must not claim a
reliable oracle).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cvepatch.core.schemas import iter_errors


class DefensiveManifestError(Exception):
    """Base for defensive-task manifest problems."""


class DefensiveManifestSchemaError(DefensiveManifestError):
    """Manifest failed JSON Schema validation."""

    def __init__(self, errors: list[str]):
        super().__init__(
            "defensive task schema violations:\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
        self.errors = errors


class DefensiveManifestConsistencyError(DefensiveManifestError):
    """Manifest is schema-valid but internally inconsistent."""


# Strategies and the trusted checks they REQUIRE for a PATCH_VERIFIED verdict.
_STRATEGY_REQUIRES_REGRESSION = {"regression", "regression_plus_existing", "differential"}
_STRATEGY_REQUIRES_EXISTING = {"regression_plus_existing"}
_CHECKOUT_MODES = {"copy", "git"}


@dataclass(frozen=True)
class DefensiveTask:
    """A validated, normalized defensive task manifest.

    `raw` is the source of truth; the typed fields exist so callers avoid
    dict-spelunking. Read-only (frozen) — the grader must never mutate task
    definition.
    """

    task_id: str
    product: str
    component: str
    vulnerability_class: str
    source_repository: str
    vulnerable_commit: str
    validation_strategy: str
    expected_baseline_result: str
    expected_patched_result: str
    network_policy: str
    task_status: str
    cve_id: str | None
    chromium_issue_id: str | None
    fixed_commit: str | None
    patch_commit: str | None
    cwe_ids: tuple[str, ...]
    affected_versions: tuple[str, ...]
    patched_files_allowlist: tuple[str, ...]
    patch_provenance: dict[str, Any]
    build_instructions: dict[str, Any]
    regression_test_command: dict[str, Any] | None
    existing_test_command: dict[str, Any] | None
    security_checks: tuple[dict[str, Any], ...]
    resource_limits: dict[str, Any]
    evidence: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def requires_regression(self) -> bool:
        return self.validation_strategy in _STRATEGY_REQUIRES_REGRESSION

    @property
    def requires_existing_tests(self) -> bool:
        return self.validation_strategy in _STRATEGY_REQUIRES_EXISTING

    @property
    def has_reliable_oracle(self) -> bool:
        """True when a regression oracle exists (non-null regression command).

        `manual_only` strategy or a missing regression command means no
        reliable oracle; the verdict is capped at INCONCLUSIVE / MANUAL_REVIEW.
        """
        return (
            self.validation_strategy != "manual_only"
            and self.regression_test_command is not None
        )

    @property
    def provenance_required(self) -> bool:
        """Whether PATCH_VERIFIED requires established patch provenance.

        A task whose provenance status is 'absent' (no known upstream fix)
        cannot have provenance *verified*; such tasks set
        `metadata.provenance_required = false` to opt out, otherwise
        provenance is required.
        """
        return bool(self.metadata.get("provenance_required", True))

    @property
    def checkout_mode(self) -> str:
        """How the grader and agent workspace get a source tree.

        'copy' (default) copies the trusted tree per checkout; 'git' uses it in
        place and resets with git afterwards — for large trees like V8.
        """
        return str(self.metadata.get("checkout_mode", "copy"))


def _load_text(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".yaml", ".yml"):
        loaded = yaml.safe_load(text)
    elif suffix == ".json":
        loaded = json.loads(text)
    else:
        raise DefensiveManifestError(f"unsupported manifest extension: {path}")
    if not isinstance(loaded, dict):
        raise DefensiveManifestError(
            f"defensive task manifest must be a mapping at top level: {path}"
        )
    return loaded


def _check_consistency(raw: dict[str, Any]) -> None:
    mode = (raw.get("metadata") or {}).get("checkout_mode", "copy")
    if mode not in _CHECKOUT_MODES:
        raise DefensiveManifestConsistencyError(
            f"metadata.checkout_mode must be one of {sorted(_CHECKOUT_MODES)}, got {mode!r}"
        )
    strategy = raw["validation_strategy"]
    reg = raw.get("regression_test_command")

    if strategy in _STRATEGY_REQUIRES_REGRESSION and reg is None:
        raise DefensiveManifestConsistencyError(
            f"validation_strategy={strategy!r} requires a non-null "
            f"regression_test_command"
        )
    if strategy in _STRATEGY_REQUIRES_EXISTING and raw.get("existing_test_command") is None:
        raise DefensiveManifestConsistencyError(
            f"validation_strategy={strategy!r} requires a non-null "
            f"existing_test_command"
        )
    if strategy == "manual_only" and reg is not None:
        raise DefensiveManifestConsistencyError(
            "validation_strategy='manual_only' must not declare a "
            "regression_test_command (a reliable oracle contradicts "
            "manual-only); use 'regression' instead"
        )

    # A reproducible task (baseline expected to FAIL the regression) needs an
    # actual regression oracle to confirm reproduction.
    if raw["expected_baseline_result"] == "regression_fail" and reg is None:
        raise DefensiveManifestConsistencyError(
            "expected_baseline_result='regression_fail' requires a "
            "regression_test_command to confirm the baseline reproduces the bug"
        )

    # Provenance 'verified' must carry a content hash + source (not just a link).
    prov = raw["patch_provenance"]
    if prov.get("status") == "verified" and not prov.get("content_sha256"):
        raise DefensiveManifestConsistencyError(
            "patch_provenance.status='verified' requires a content_sha256 "
            "(an advisory link alone is not proof)"
        )


def from_dict(raw: dict[str, Any]) -> DefensiveTask:
    """Validate `raw` against the schema + consistency rules, then project."""
    errors = iter_errors("defensive_task", raw)
    if errors:
        raise DefensiveManifestSchemaError(errors)
    _check_consistency(raw)

    return DefensiveTask(
        task_id=raw["task_id"],
        product=raw["product"],
        component=raw["component"],
        vulnerability_class=raw["vulnerability_class"],
        source_repository=raw["source_repository"],
        vulnerable_commit=raw["vulnerable_commit"],
        validation_strategy=raw["validation_strategy"],
        expected_baseline_result=raw["expected_baseline_result"],
        expected_patched_result=raw["expected_patched_result"],
        network_policy=raw["network_policy"],
        task_status=raw["task_status"],
        cve_id=raw.get("cve_id"),
        chromium_issue_id=raw.get("chromium_issue_id"),
        fixed_commit=raw.get("fixed_commit"),
        patch_commit=raw.get("patch_commit"),
        cwe_ids=tuple(raw.get("cwe_ids") or ()),
        affected_versions=tuple(raw.get("affected_versions") or ()),
        patched_files_allowlist=tuple(raw.get("patched_files_allowlist") or ()),
        patch_provenance=dict(raw["patch_provenance"]),
        build_instructions=dict(raw["build_instructions"]),
        regression_test_command=(
            dict(raw["regression_test_command"])
            if raw.get("regression_test_command") is not None
            else None
        ),
        existing_test_command=(
            dict(raw["existing_test_command"])
            if raw.get("existing_test_command") is not None
            else None
        ),
        security_checks=tuple(raw.get("security_checks") or ()),
        resource_limits=dict(raw.get("resource_limits") or {}),
        evidence=tuple(raw["evidence"]),
        limitations=tuple(raw.get("limitations") or ()),
        metadata=dict(raw.get("metadata") or {}),
        raw=raw,
    )


def load(path: str | Path) -> DefensiveTask:
    """Read a defensive task manifest (YAML or JSON) and return a DefensiveTask."""
    return from_dict(_load_text(Path(path)))
