"""Trusted validation pipeline A-G (spec §15.7-12, §10).

These exercise the REAL pipeline against the synthetic fixture: baseline
reproduction, build failure, regression failure, successful verification,
missing oracle, and the test-suppression negative case. Requires a C
compiler; skipped otherwise.
"""

from __future__ import annotations

import difflib
import shutil
from pathlib import Path

import pytest

from cvepatch.core import manifest as M
from cvepatch.core.validation import pipeline as P

_CC = shutil.which("cc") or shutil.which("gcc")
pytestmark = pytest.mark.skipif(_CC is None, reason="no C compiler available")

FIXTURE = Path("testenvs/defensive-fixture")
BASELINE = FIXTURE / "baseline"
TASK = FIXTURE / "task" / "defensive_task.json"
REF_PATCH = (FIXTURE / "reference" / "fix.patch").read_text()


def _task():
    return M.load(TASK)


def _strbuf_src() -> str:
    return (BASELINE / "src" / "strbuf.c").read_text()


def _diff_for(new_src: str) -> str:
    orig = _strbuf_src()
    return "".join(difflib.unified_diff(
        orig.splitlines(keepends=True), new_src.splitlines(keepends=True),
        fromfile="a/src/strbuf.c", tofile="b/src/strbuf.c"))


def test_successful_patch_verified(tmp_path):
    res = P.validate(_task(), BASELINE, REF_PATCH, work_root=tmp_path).to_dict()
    assert res["final_status"] == "PATCH_VERIFIED"
    d = res["dimensions"]
    assert d["baseline_reproduced"] is True
    assert d["candidate_build_passed"] is True
    assert d["regression_test_passed"] is True
    assert d["existing_tests_passed"] is True
    assert d["false_positive"] is False


def test_baseline_reproduces_the_defect(tmp_path):
    # Submit an empty-but-allowed patch to observe step B in isolation.
    res = P.validate(_task(), BASELINE, REF_PATCH, work_root=tmp_path).to_dict()
    step_b = next(s for s in res["steps"] if s["step"] == "B")
    assert step_b["status"] == "pass"
    assert "oracle_passed=False" in (step_b["detail"] or "")


def test_build_failure_is_not_a_fix(tmp_path):
    broken = _strbuf_src().replace("return n;", "return n")  # drop semicolon
    res = P.validate(_task(), BASELINE, _diff_for(broken), work_root=tmp_path).to_dict()
    assert res["final_status"] != "PATCH_VERIFIED"
    assert res["dimensions"]["candidate_build_passed"] is False


def test_regression_still_failing_is_false_positive(tmp_path):
    # Cosmetic change: compiles, but the off-by-one is untouched.
    cosmetic = _strbuf_src().replace(
        "if (n > cap) {", "if (n > cap) { /* unchanged logic */")
    res = P.validate(_task(), BASELINE, _diff_for(cosmetic), work_root=tmp_path).to_dict()
    assert res["final_status"] != "PATCH_VERIFIED"
    assert res["dimensions"]["regression_test_passed"] is False
    assert res["dimensions"]["false_positive"] is True


def test_test_suppression_patch_fails_existing_tests(tmp_path):
    # Neuter the function: regression (guard) passes, functional breaks.
    neutered = _strbuf_src()
    body_start = neutered.index("    size_t n = strlen(src);")
    neutered = neutered[:body_start] + "    dst[0] = '\\0';\n    return 0;\n}\n"
    res = P.validate(_task(), BASELINE, _diff_for(neutered), work_root=tmp_path).to_dict()
    assert res["final_status"] != "PATCH_VERIFIED"
    assert res["dimensions"]["regression_test_passed"] is True
    assert res["dimensions"]["existing_tests_passed"] is False
    assert res["dimensions"]["false_positive"] is True


def test_missing_oracle_is_manual_review(tmp_path):
    raw = _task().raw.copy()
    raw["regression_test_command"] = None
    raw["existing_test_command"] = None
    raw["validation_strategy"] = "manual_only"
    raw["expected_baseline_result"] = "unknown"
    task = M.from_dict(raw)
    res = P.validate(task, BASELINE, REF_PATCH, work_root=tmp_path).to_dict()
    assert res["final_status"] == "MANUAL_REVIEW"


def test_empty_patch_cannot_be_verified(tmp_path):
    res = P.validate(_task(), BASELINE, "", work_root=tmp_path).to_dict()
    assert res["final_status"] != "PATCH_VERIFIED"
    assert res["dimensions"]["patch_format_valid"] is False


def test_out_of_allowlist_patch_rejected(tmp_path):
    cheat = """--- a/tests/regression_test.c
+++ b/tests/regression_test.c
@@ -1 +1 @@
-x
+y
"""
    res = P.validate(_task(), BASELINE, cheat, work_root=tmp_path).to_dict()
    assert res["dimensions"]["patch_format_valid"] is False
    assert res["final_status"] != "PATCH_VERIFIED"


def test_build_timeout_records_infra(tmp_path):
    raw = _task().raw.copy()
    raw["build_instructions"] = dict(raw["build_instructions"])
    raw["build_instructions"]["command"] = ["sleep", "5"]
    raw["build_instructions"]["timeout_s"] = 1
    task = M.from_dict(raw)
    res = P.validate(task, BASELINE, REF_PATCH, work_root=tmp_path).to_dict()
    # sleep "builds" (exit 0 after kill? no — killed -> nonzero/timeout). The
    # candidate build then reports not-passed; never PATCH_VERIFIED.
    assert res["final_status"] != "PATCH_VERIFIED"


def test_result_validates_against_schema(tmp_path):
    from cvepatch.core.schemas import iter_errors
    res = P.validate(_task(), BASELINE, REF_PATCH, work_root=tmp_path).to_dict()
    assert iter_errors("validation_result", res) == []
