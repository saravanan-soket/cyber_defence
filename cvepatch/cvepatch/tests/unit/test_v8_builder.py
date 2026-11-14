"""V8 defensive builder emits the REAL bench-v8 bootstrap CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cvepatch.core.env_builder.v8_builder import V8DefensiveBuilder

FIXTURE_TASK = Path("testenvs/defensive-fixture/task/defensive_task.json")


def _builder(tmp_path, **overrides) -> V8DefensiveBuilder:
    raw = json.loads(FIXTURE_TASK.read_text())
    raw.update(overrides)
    p = tmp_path / "task.json"
    p.write_text(json.dumps(raw))
    return V8DefensiveBuilder(task_path=p, bench_v8_dir=Path("benchmarks/bench-v8"),
                              work_root=tmp_path / "w")


def test_cve_with_crbug_and_fix_commit(tmp_path):
    b = _builder(tmp_path, cve_id="CVE-2024-4761", chromium_issue_id="crbug-339458194",
                 fixed_commit="abc1234")
    cmd = b.bootstrap_command()
    assert cmd[2:] == ["bug", "CVE-2024-4761", "--pair", "b/339458194", "--commit", "abc1234"]
    assert "--bug" not in cmd and "--crev" not in cmd


def test_crbug_only(tmp_path):
    b = _builder(tmp_path, cve_id=None, chromium_issue_id="crbug-378779897", fixed_commit=None)
    assert b.bootstrap_command()[2:] == ["bug", "b/378779897"]


def test_requires_an_identifier(tmp_path):
    b = _builder(tmp_path, cve_id=None, chromium_issue_id=None)
    with pytest.raises(ValueError):
        b.bootstrap_command()
