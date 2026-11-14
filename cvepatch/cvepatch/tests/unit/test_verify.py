"""cvepatch verifier tiers + the agent's submit_fix flow, on the C fixture.

Runs on the host (needs a C compiler and git, like the pipeline tests); no
Docker, no network.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cvepatch.core.mcp_server.tools import DefensiveToolbox
from cvepatch.core.verifier.verify import find_submission, verify

FIXTURE = Path(__file__).resolve().parents[3] / "testenvs" / "cvepatch-fixture"

pytestmark = pytest.mark.skipif(shutil.which("cc") is None or shutil.which("git") is None,
                                reason="needs cc + git")

AGENT_TEST = r"""
#include "strbuf.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    struct { char buf[4]; unsigned char canary; } g;
    memset(&g, 0, sizeof g); g.canary = 0x5A;
    strbuf_copy(g.buf, sizeof g.buf, "abcd");
    if (g.canary != 0x5A) { fprintf(stderr, "canary clobbered\n"); return 1; }
    return 0;
}
"""
TRIVIAL_TEST = '#include "strbuf.h"\nint main(void) { return 0; }\n'
NEW_API_TEST = '#include "strbuf.h"\nint main(void) { return strbuf_copy_checked(0, 0, "") ; }\n'
FIXED_SRC_OLD = "    if (n > cap) {\n        n = cap;\n"
FIXED_SRC_NEW = "    if (n >= cap) {\n        n = cap - 1;\n"


def _box(tmp: Path) -> DefensiveToolbox:
    src = tmp / "src"
    shutil.copytree(FIXTURE / "baseline", src)
    return DefensiveToolbox(source_dir=src, workspace_dir=tmp / "ws",
                            task_path=FIXTURE / "public" / "defensive_task.json")


def _submit(tmp: Path, test_src: str, *, fix: bool = True, extra_fix: str = "") -> Path:
    """Drive the real toolbox like an agent would, and record its submit_fix."""
    box = _box(tmp)
    assert box.write_file("tests/agent_test.c", test_src)["ok"]
    c = box.candidate_dir / "src" / "strbuf.c"
    text = c.read_text()
    text = text.replace(FIXED_SRC_OLD, FIXED_SRC_NEW) if fix else text + "/* touched */\n"
    c.write_text(text + extra_fix)
    res = box.submit_fix(["tests/agent_test.c"], "bash build.sh && ./build/agent_test")
    assert res["ok"], res
    run = tmp / "run"
    run.mkdir()
    (run / "tool_calls.jsonl").write_text(json.dumps(
        {"tool": "submit_fix", "args": {}, "result": json.dumps(res)}) + "\n")
    return run


def _hidden(tmp: Path, *, oracle: bool = True, reference: bool = True) -> Path:
    h = tmp / "hidden"
    shutil.copytree(FIXTURE / "hidden", h)
    if not oracle:
        shutil.rmtree(h / "oracle")
    if not reference:
        shutil.rmtree(h / "reference")
    return h


def _verify(tmp: Path, run: Path, hidden: Path) -> dict:
    return verify(run_dir=run, baseline=FIXTURE / "baseline", hidden=hidden,
                  work_root=tmp / "work", repeats=1)


def test_good_fix_and_test_is_t1(tmp_path):
    out = _verify(tmp_path, _submit(tmp_path, AGENT_TEST), _hidden(tmp_path))
    assert out["tier"] == "T1", out["steps"]
    c = out["checks"]
    assert c["agent_test_fails_on_vuln"] and c["agent_test_passes_on_fix"]
    assert c["upstream_test_fails_on_vuln"] and c["upstream_test_passes_on_fix"]
    assert c["agent_test_passes_on_upstream_fix"] and c["existing_tests_passed"]
    assert out["final_status"] == "PATCH_VERIFIED"


def test_without_upstream_tests_cross_check_gives_t2(tmp_path):
    out = _verify(tmp_path, _submit(tmp_path, AGENT_TEST), _hidden(tmp_path, oracle=False))
    assert out["tier"] == "T2"


def test_self_consistent_only_is_t4(tmp_path):
    out = _verify(tmp_path, _submit(tmp_path, AGENT_TEST),
                  _hidden(tmp_path, oracle=False, reference=False))
    assert out["tier"] == "T4" and out["final_status"] == "MANUAL_REVIEW"


def test_test_that_passes_on_vulnerable_code_is_rejected(tmp_path):
    out = _verify(tmp_path, _submit(tmp_path, TRIVIAL_TEST), _hidden(tmp_path))
    assert out["tier"] == "rejected"
    assert out["checks"]["agent_test_fails_on_vuln"] is False


def test_fix_that_does_not_fix_is_rejected(tmp_path):
    out = _verify(tmp_path, _submit(tmp_path, AGENT_TEST, fix=False), _hidden(tmp_path))
    assert out["tier"] == "rejected"
    assert out["checks"]["agent_test_passes_on_fix"] is False
    assert out["checks"]["upstream_test_passes_on_fix"] is False


def test_test_needing_the_agents_new_api_is_rejected(tmp_path):
    extra = ("\nint strbuf_copy_checked(char *d, size_t c, const char *s)"
             " { (void)d; (void)c; (void)s; return 0; }\n")
    out = _verify(tmp_path, _submit(tmp_path, NEW_API_TEST, extra_fix=extra), _hidden(tmp_path))
    assert out["tier"] == "rejected"
    assert out["checks"]["agent_test_fails_on_vuln"] is False
    assert any("does not compile" in s["detail"] for s in out["steps"])


def test_no_submission_is_rejected(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    out = _verify(tmp_path, run, _hidden(tmp_path))
    assert out["tier"] == "rejected" and out["submission"] is None
    assert find_submission(run) is None


# ------------------------------------------------------------------ tools
def test_submit_fix_splits_test_from_fix(tmp_path):
    box = _box(tmp_path)
    box.write_file("tests/agent_test.c", AGENT_TEST)
    c = box.candidate_dir / "src" / "strbuf.c"
    c.write_text(c.read_text().replace(FIXED_SRC_OLD, FIXED_SRC_NEW))
    res = box.submit_fix(["tests/agent_test.c"], "bash build.sh && ./build/agent_test")
    assert res["ok"] and res["fix_files"] == ["src/strbuf.c"]
    assert "tests/agent_test.c" in res["test_patch"] and "src/strbuf.c" not in res["test_patch"]
    assert "src/strbuf.c" in res["fix_patch"] and "agent_test" not in res["fix_patch"]


def test_submit_fix_rejects_bad_submissions(tmp_path):
    box = _box(tmp_path)
    box.write_file("tests/agent_test.c", AGENT_TEST)
    assert "no fix" in box.submit_fix(["tests/agent_test.c"], "true")["error"]
    assert "not changed" in box.submit_fix(["tests/other.c"], "true")["error"]
    assert "empty" in box.submit_fix([], "true")["error"]


def test_write_file_and_run_command_stay_in_workspace(tmp_path):
    box = _box(tmp_path)
    assert not box.write_file("../escape.txt", "x")["ok"]
    assert not box.write_file("/etc/passwd", "x")["ok"]
    r = box.run_command("bash build.sh >/dev/null && ./build/functional_test")
    assert r["exitcode"] == 0
    assert box.run_command("pwd")["stdout"].strip() == str(box.candidate_dir)


def test_public_task_hides_the_answer():
    pub = (FIXTURE / "public" / "defensive_task.json").read_text()
    hidden = json.loads((FIXTURE / "hidden" / "task.json").read_text())
    assert "regression_test.c" not in pub and "oracle" not in pub
    assert hidden["patch_provenance"]["content_sha256"] not in pub
    p = json.loads(pub)
    assert p["fixed_commit"] is None and p["existing_test_command"] is None
    assert p["metadata"]["advisory"]["description"]


def test_setup_gives_advisory_and_workflow(tmp_path):
    s = _box(tmp_path).setup()
    assert "CWE-787" in json.dumps(s["advisory"])
    assert "submit_fix" in s["instructions"] and "FAILS" in s["instructions"]
    # No allowlisted test runners on cvepatch tasks (legacy tools are off).
    assert "available_tests" not in s and "run_tests" not in s["task_profile"]["episode_tools"]
