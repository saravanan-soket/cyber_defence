"""Manifest schema + interface-consistency tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from cvepatch.contract.manifest import (
    ManifestInterfaceError,
    ManifestSchemaError,
    from_dict,
    load,
    load_schema,
)

FIXTURES = Path(__file__).parent.parent / "golden" / "manifests"


def test_schema_loads_and_has_expected_top_level_keys() -> None:
    schema = load_schema()
    required = set(schema["required"])
    assert {"schema_version", "env_id", "interface", "image", "task_type", "evaluate"} <= required


FIXTURE_MANIFEST = (Path(__file__).resolve().parents[3] / "testenvs" / "defensive-fixture"
                    / "env_manifest.yaml")


def _fixture_raw() -> dict:
    return yaml.safe_load(FIXTURE_MANIFEST.read_text())


def test_defensive_manifest_loads_cleanly() -> None:
    m = load(FIXTURE_MANIFEST)
    assert m.env_id == "defensive-fixture-strbuf-01"
    assert m.interface == "rl.mcp.vulnerability_defense.v1"
    assert m.grader_kind == "cli_oneshot"


def test_unknown_interface_rejected_by_consistency_check() -> None:
    with pytest.raises(ManifestInterfaceError) as exc:
        load(FIXTURES / "invalid_unknown_interface.yaml")
    assert "rl.mcp.totally_fake.v1" in str(exc.value)


def test_missing_required_fields_rejected_by_schema() -> None:
    with pytest.raises(ManifestSchemaError) as exc:
        load(FIXTURES / "invalid_missing_required.yaml")
    assert "evaluate" in str(exc.value)


def test_unknown_top_level_key_rejected() -> None:
    """additionalProperties=false at the top — typo guard."""
    raw = {
        "schema_version": "1",
        "env_id": "x",
        "interface": "rl.mcp.vulnerability_defense.v1",
        "task_type": "binary_patch",
        "image": {"ref": "local/x:latest"},
        "evaluate": {"kind": "mcp_tool", "tool": "grade"},
        "mcp": {"episode_tools": ["grade"]},
        "i_meant_metadata": {},
    }
    with pytest.raises(ManifestSchemaError):
        from_dict(raw)


def test_episode_tool_not_in_interface_rejected() -> None:
    raw = _fixture_raw()
    raw["mcp"]["episode_tools"] = [*raw["mcp"]["episode_tools"], "totally_made_up_tool"]
    with pytest.raises(ManifestInterfaceError) as exc:
        from_dict(raw)
    assert "totally_made_up_tool" in str(exc.value)


def test_expected_capability_outside_interface_bitmap_rejected() -> None:
    raw = _fixture_raw()
    raw["expected_capabilities"] = ["regression_test_passed", "not_a_dimension"]
    with pytest.raises(ManifestInterfaceError) as exc:
        from_dict(raw)
    assert "not_a_dimension" in str(exc.value)


def test_image_ref_starting_with_dash_rejected_by_schema() -> None:
    """Defense: a manifest can't smuggle a docker-run flag as image.ref."""
    raw = {
        "schema_version": "1",
        "env_id": "x",
        "interface": "rl.mcp.vulnerability_defense.v1",
        "task_type": "binary_patch",
        "image": {"ref": "-v=/host:/inside"},
        "mcp": {"episode_tools": ["setup", "exec", "grade"]},
        "evaluate": {"kind": "mcp_tool", "tool": "grade"},
    }
    with pytest.raises(ManifestSchemaError):
        from_dict(raw)


