"""Runner/DB integration + offensive backward-compat (spec §13, §15.13-16)."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from cvepatch.contract import manifest as envman

ENV_MANIFEST = Path("testenvs/defensive-fixture/env_manifest.yaml")


def _raw_env_manifest() -> dict:
    return yaml.safe_load(ENV_MANIFEST.read_text())


# -- catalog registration -> orchestrator manifest lookup (§13) ------------
def test_register_defensive_env_and_manifest_lookup(tmp_path, monkeypatch):
    db = tmp_path / "db.sqlite"
    monkeypatch.setenv("CVEPATCH_DB", str(db))
    from cvepatch.catalog import get_env, register_defensive_env
    from cvepatch.runner.env_manifest import load_env_manifest

    was_new = register_defensive_env(ENV_MANIFEST, db_path=db)
    assert was_new is True
    row = get_env("defensive-fixture-strbuf-01", db_path=db)
    assert row["interface"] == "rl.mcp.vulnerability_defense.v1"
    assert row["task_type"] == "binary_patch"
    assert row["metadata"]["manifest_path"].endswith("env_manifest.yaml")

    m = load_env_manifest("defensive-fixture-strbuf-01")
    assert m is not None
    assert m.grader_kind == "cli_oneshot"
    assert m.grader_command[:3] == ("python", "-m",
                                    "cvepatch.core.verifier.deterministic_grader")


# -- manifest reward-hacking guard (§9, §15.13) ----------------------------
def test_evaluation_tool_in_episode_tools_is_rejected():
    raw = _raw_env_manifest()
    raw["mcp"]["episode_tools"].append("grade_defensive")  # try to expose grader
    with pytest.raises(envman.ManifestInterfaceError):
        envman.from_dict(raw)


def test_unknown_episode_tool_rejected():
    raw = _raw_env_manifest()
    raw["mcp"]["episode_tools"].append("rm_rf_slash")
    with pytest.raises(envman.ManifestInterfaceError):
        envman.from_dict(raw)


def test_cli_oneshot_interface_requires_cli_oneshot_grading():
    raw = _raw_env_manifest()
    raw["evaluate"] = {"kind": "mcp_tool", "tool": "grade"}
    # Rejected either at schema level (interface_flavor=rl_mcp_v1 pins
    # evaluate.kind=cli_oneshot) or at the interface cross-check — both are
    # ManifestError subclasses. Either way the defensive grader can't be
    # downgraded to an in-episode tool.
    with pytest.raises(envman.ManifestError):
        envman.from_dict(raw)


# -- DB schema is unchanged (no migration needed) (§13, §15.15) ------------
def test_db_schema_version_unchanged(tmp_path, monkeypatch):
    db = tmp_path / "db.sqlite"
    monkeypatch.setenv("CVEPATCH_DB", str(db))
    from cvepatch.db.schema import SCHEMA_VERSION, connect, init_db

    init_db(db)
    with connect(db) as con:
        v = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    assert int(v["value"]) == SCHEMA_VERSION  # defensive work added NO migration


# -- offensive workflow regression (§15.16) --------------------------------
def test_orchestrator_imports_scoring_dispatch():
    # The orchestrator must route scoring through the interface-aware dispatch.
    import cvepatch.runner.orchestrator as orch

    assert hasattr(orch, "score_for_interface")


def test_benchmark_configs_parse():
    from cvepatch.runner.orchestrator_config import parse_config

    for f in ("benchmarks/defensive-fixture.yaml", "benchmarks/defensive-v8.yaml"):
        cfg = parse_config(copy.deepcopy(yaml.safe_load(Path(f).read_text())))
        assert cfg.envs[0].interface == "rl.mcp.vulnerability_defense.v1"
        assert cfg.envs[0].task_type == "binary_patch"
