"""Grader entrypoint + hidden-grader isolation (spec §9, §15.10, §15.13)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cvepatch.contract import interfaces
from cvepatch.contract import manifest as envman
from cvepatch.core import DEFENSIVE_INTERFACE
from cvepatch.core.mcp_server.tools import DefensiveToolbox
from cvepatch.core.verifier import deterministic_grader as G

FIXTURE = Path("testenvs/defensive-fixture")
BASELINE = FIXTURE / "baseline"
TASK = FIXTURE / "task" / "defensive_task.json"
ENV_MANIFEST = FIXTURE / "env_manifest.yaml"
REF_PATCH = (FIXTURE / "reference" / "fix.patch").read_text()

_CC = shutil.which("cc") or shutil.which("gcc")


# -- hidden-grader isolation (does not need a compiler) --------------------
def test_grade_defensive_is_evaluation_tool_not_episode_tool():
    m = envman.load(ENV_MANIFEST)
    assert "grade_defensive" in m.evaluation_tools
    assert "grade_defensive" not in m.episode_tools
    # disjointness is enforced by the contract validator (load() above would
    # have raised otherwise); assert explicitly for clarity.
    assert set(m.episode_tools).isdisjoint(set(m.evaluation_tools))


def test_setup_does_not_leak_the_fix(tmp_path):
    box = DefensiveToolbox(
        source_dir=BASELINE, workspace_dir=tmp_path / "ws", task_path=TASK,
    )
    s = box.setup()
    blob = json.dumps(s)
    assert "fixed_commit" not in s["task"]
    assert "patch_provenance" not in s["task"]
    # The reference-patch sha / fixed-commit must not appear anywhere in setup.
    assert "fix.patch" not in blob
    assert box.task.patch_provenance["content_sha256"] not in blob


def test_toolbox_rejects_path_traversal(tmp_path):
    box = DefensiveToolbox(source_dir=BASELINE, workspace_dir=tmp_path / "ws", task_path=TASK)
    assert "error" in box.read_file("../../../../etc/passwd")
    assert "error" in box.list_directory("/etc")


def test_interface_flags_are_defensive_not_offensive():
    iface = interfaces.lookup(DEFENSIVE_INTERFACE)
    assert "ace" not in iface.capability_flags
    assert "regression_test_passed" in iface.capability_flags
    assert iface.grader_kind == "cli_oneshot"


# -- grader reads the submitted patch from the transcript ------------------
@pytest.mark.skipif(_CC is None, reason="no C compiler available")
def test_grader_reads_patch_from_transcript_and_verifies(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    submit_result = {"ok": True, "patch": REF_PATCH, "base_revision": None}
    (run_dir / "tool_calls.jsonl").write_text(
        json.dumps({"tool": "submit_patch", "args": {}, "result": json.dumps(submit_result)}) + "\n"
    )
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] == "PATCH_VERIFIED"
    assert out["capabilities"]["regression_test_passed"] is True


@pytest.mark.skipif(_CC is None, reason="no C compiler available")
def test_grader_inline_args_patch_also_found(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "tool_calls.jsonl").write_text(
        json.dumps({"tool": "submit_patch", "args": {"patch": REF_PATCH}, "result": "{}"}) + "\n"
    )
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] == "PATCH_VERIFIED"


def test_grader_no_submission_is_not_verified(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "tool_calls.jsonl").write_text(
        json.dumps({"tool": "read_file", "args": {"path": "src/strbuf.c"}, "result": "{}"}) + "\n"
    )
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] != "PATCH_VERIFIED"
    assert out["dimensions"]["patch_format_valid"] is False


def test_grader_cli_emits_json(tmp_path, capsys):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "tool_calls.jsonl").write_text("")
    rc = G.main(["--run", str(run_dir), "--task", str(TASK),
                 "--baseline", str(BASELINE), "--work-root", str(tmp_path / "w")])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["schema_version"] == "1"
    assert "capabilities" in out
