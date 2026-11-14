"""End-to-end defensive workflow on the synthetic fixture (spec §15 e2e).

No Docker and no LLM: drives the EnvironmentBuilder + MCP toolbox + trusted
grader directly, which is the same code the container path runs.

  * baseline reproduces a known failure;
  * a (fixture) patch fixes the defect, builds, and passes regression;
  * the grader returns PATCH_VERIFIED;
  * a patch that merely suppresses the test (breaks functionality) or fails
    to build does NOT receive a verified verdict.

Requires a C compiler; skipped otherwise.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cvepatch.core.env_builder.fixture_builder import FixtureBuilder
from cvepatch.core.mcp_server.tools import DefensiveToolbox
from cvepatch.core.verifier import deterministic_grader as G

_FIXTURE_TESTS = {
    "build": ["bash", "build.sh"],
    "regression": ["./build/regression_test"],
    "functional": ["./build/functional_test"],
}

_CC = shutil.which("cc") or shutil.which("gcc")
pytestmark = pytest.mark.skipif(_CC is None, reason="no C compiler available")

FIXTURE = Path("testenvs/defensive-fixture")
BASELINE = FIXTURE / "baseline"
TASK = FIXTURE / "task" / "defensive_task.json"
REF_PATCH = (FIXTURE / "reference" / "fix.patch").read_text()


def _write_transcript(run_dir: Path, patch: str) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    submit = {"ok": True, "patch": patch, "base_revision": None}
    (run_dir / "tool_calls.jsonl").write_text(
        json.dumps({"tool": "submit_patch", "args": {}, "result": json.dumps(submit)}) + "\n")


def test_builder_confirms_baseline_fails_and_fix_passes(tmp_path):
    b = FixtureBuilder(baseline_src=BASELINE, task_path=TASK, work_root=tmp_path / "wb")
    base = b.prepare_baseline()
    b.pin_dependencies(base)
    assert b.build(base).ok
    assert b.run_baseline_regression(base)["passed"] is False  # vulnerable

    cand = b.prepare_candidate_workspace(base)
    # apply the fixture patch into the candidate workspace
    import subprocess
    (cand.path / ".p").write_text(REF_PATCH)
    subprocess.run(["git", "apply", "-p1", ".p"], cwd=cand.path, check=True)
    assert b.build(cand).ok
    assert b.run_patched_regression(cand)["passed"] is True  # fixed


def test_full_agent_to_grader_happy_path(tmp_path):
    # 1. Agent iterates a fix via the MCP toolbox.
    box = DefensiveToolbox(source_dir=BASELINE, workspace_dir=tmp_path / "ws", task_path=TASK,
                           allowed_test_commands=_FIXTURE_TESTS)
    assert box.apply_patch(REF_PATCH)["ok"] is True
    # build then run the public tests the defender is allowed to use
    box.run_tests("build")
    tests = box.run_tests("all")["results"]
    assert tests["regression"]["exitcode"] == 0
    assert tests["functional"]["exitcode"] == 0
    sub = box.submit_patch(patch=REF_PATCH)
    assert sub["ok"] is True

    # 2. Host-written transcript carries the submission to the fresh grader.
    run_dir = tmp_path / "run"
    _write_transcript(run_dir, sub["patch"])

    # 3. Trusted grader verdict.
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] == "PATCH_VERIFIED"
    assert out["dimensions"]["false_positive"] is False


def test_full_path_rejects_suppression_patch(tmp_path):
    src = (BASELINE / "src" / "strbuf.c").read_text()
    body_start = src.index("    size_t n = strlen(src);")
    neutered = src[:body_start] + "    dst[0] = '\\0';\n    return 0;\n}\n"
    import difflib
    diff = "".join(difflib.unified_diff(
        src.splitlines(keepends=True), neutered.splitlines(keepends=True),
        fromfile="a/src/strbuf.c", tofile="b/src/strbuf.c"))

    run_dir = tmp_path / "run"
    _write_transcript(run_dir, diff)
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] != "PATCH_VERIFIED"
    assert out["dimensions"]["existing_tests_passed"] is False
    assert out["dimensions"]["false_positive"] is True


def test_full_path_with_report_evaluates_separately(tmp_path):
    run_dir = tmp_path / "run"
    report = {
        "schema_version": "1", "task_id": "fixture-strbuf-off-by-one-01",
        "vulnerability_summary": "off-by-one", "root_cause": "clamp to cap not cap-1",
        "affected_file": "src/strbuf.c", "affected_line_range": [14, 26],
        "security_invariant_violated": "no write past dst[cap-1]",
        "proposed_fix": "clamp n to cap-1", "tests_executed": ["regression"],
    }
    run_dir.mkdir()
    lines = [
        {"tool": "submit_report", "args": {"report": report}, "result": "{}"},
        {"tool": "submit_patch", "args": {},
         "result": json.dumps({"ok": True, "patch": REF_PATCH})},
    ]
    (run_dir / "tool_calls.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    out = G.grade(run_dir=run_dir, task_path=TASK, baseline_dir=BASELINE,
                  work_root=tmp_path / "work")
    assert out["final_status"] == "PATCH_VERIFIED"
    assert out["report"] is not None
    assert out["dimensions"]["root_cause_supported"] is True
