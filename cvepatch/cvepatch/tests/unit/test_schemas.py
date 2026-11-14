"""Defensive schema loading + manifest validation (task spec §15.1, §15.14)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cvepatch.core import manifest as M
from cvepatch.core.schemas import iter_errors, load_schema

FIXTURE_TASK = Path("testenvs/defensive-fixture/task/defensive_task.json")


def _valid_raw() -> dict:
    return json.loads(FIXTURE_TASK.read_text())


def test_all_schemas_load():
    for name in ("defensive_task", "patch_submission", "validation_result",
                 "root_cause_report"):
        s = load_schema(name)
        assert s["$schema"].startswith("https://json-schema.org/")


def test_fixture_task_manifest_is_valid():
    task = M.load(FIXTURE_TASK)
    assert task.task_id == "fixture-strbuf-off-by-one-01"
    assert task.has_reliable_oracle is True
    assert task.requires_existing_tests is True
    assert task.provenance_required is True


def test_missing_required_field_rejected():
    raw = _valid_raw()
    del raw["vulnerable_commit"]
    with pytest.raises(M.DefensiveManifestSchemaError):
        M.from_dict(raw)


def test_bad_cve_pattern_rejected():
    raw = _valid_raw()
    raw["cve_id"] = "not-a-cve"
    assert any("cve_id" in e for e in iter_errors("defensive_task", raw))


def test_manual_only_with_regression_command_is_inconsistent():
    raw = _valid_raw()
    raw["validation_strategy"] = "manual_only"
    with pytest.raises(M.DefensiveManifestConsistencyError):
        M.from_dict(raw)


def test_regression_fail_baseline_requires_oracle():
    raw = _valid_raw()
    raw["regression_test_command"] = None
    raw["validation_strategy"] = "regression"  # still requires regression
    with pytest.raises(M.DefensiveManifestConsistencyError):
        M.from_dict(raw)


def test_verified_provenance_requires_content_hash():
    raw = _valid_raw()
    raw["patch_provenance"] = {"status": "verified", "source": "x", "content_sha256": None}
    with pytest.raises(M.DefensiveManifestConsistencyError):
        M.from_dict(raw)


def test_missing_metadata_is_explicit_not_invented():
    # A task with no CVE / fixed_commit must be representable (null), not forced.
    raw = _valid_raw()
    raw["cve_id"] = None
    raw["fixed_commit"] = None
    raw["patch_commit"] = None
    raw["patch_provenance"] = {"status": "absent"}
    raw["metadata"] = {"provenance_required": False}
    task = M.from_dict(raw)
    assert task.cve_id is None
    assert task.fixed_commit is None
    assert task.provenance_required is False
