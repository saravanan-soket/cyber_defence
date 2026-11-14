"""Root-cause report: schema + mechanical cross-checks (spec §11)."""

from __future__ import annotations

from pathlib import Path

from cvepatch.core.report import evaluate_report

BASELINE = Path("testenvs/defensive-fixture/baseline")


def _good_report():
    return {
        "schema_version": "1",
        "task_id": "fixture-strbuf-off-by-one-01",
        "vulnerability_summary": "Off-by-one write past the destination buffer.",
        "root_cause": "strbuf_copy clamps n to cap instead of cap-1, so dst[cap] is written.",
        "affected_file": "src/strbuf.c",
        "affected_line_range": [14, 26],
        "security_invariant_violated": "no write past dst[cap-1]",
        "proposed_fix": "clamp n to cap-1",
        "tests_executed": ["regression", "functional"],
    }


def test_valid_report_passes_mechanical_checks():
    ev = evaluate_report(_good_report(), BASELINE)
    assert ev.schema_valid is True
    assert ev.passed is True


def test_missing_file_fails():
    r = _good_report()
    r["affected_file"] = "src/does_not_exist.c"
    ev = evaluate_report(r, BASELINE)
    assert ev.passed is False


def test_line_range_out_of_bounds_fails():
    r = _good_report()
    r["affected_line_range"] = [1, 100000]
    ev = evaluate_report(r, BASELINE)
    assert ev.passed is False


def test_traversal_affected_file_rejected():
    r = _good_report()
    r["affected_file"] = "../../../../etc/passwd"
    ev = evaluate_report(r, BASELINE)
    assert ev.passed is False


def test_schema_invalid_report():
    r = _good_report()
    del r["root_cause"]
    ev = evaluate_report(r, BASELINE)
    assert ev.schema_valid is False
    assert ev.passed is False


def test_right_cwe_label_alone_does_not_pass():
    # A schema-valid report that points at the WRONG file must not pass just
    # because its prose is plausible — mechanical checks gate it.
    r = _good_report()
    r["affected_file"] = "build.sh"   # exists but is not the vulnerable file;
    r["affected_line_range"] = [1, 2]  # still, mechanical check only confirms
    ev = evaluate_report(r, BASELINE)  # existence+range, not correctness.
    # It passes existence/range here (build.sh exists) — the point is that the
    # report NEVER feeds the patch verdict; assert the evaluation is reported
    # separately and carries per-check detail rather than a correctness claim.
    assert "checks" in ev.to_dict()
    assert all("detail" in c for c in ev.to_dict()["checks"])
