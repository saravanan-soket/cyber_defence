"""Defensive scoring + interface-aware dispatch (spec §12, §13 backcompat)."""

from __future__ import annotations

from cvepatch.core.verifier.metrics import (
    DEFENSIVE_SCORING_POLICY,
    compute_defensive_score,
    defensive_policy_max,
)
from cvepatch.runner.scoring import score_for_interface


def test_defensive_verified_normalizes_to_policy_max():
    caps = {"patch_format_valid": True, "regression_test_passed": True}
    score = score_for_interface("rl.mcp.vulnerability_defense.v1", caps,
                                final_status="PATCH_VERIFIED")
    assert score == defensive_policy_max()


def test_defensive_false_positive_nullifies_score():
    caps = {"patch_format_valid": True, "candidate_build_passed": True,
            "baseline_reproduced": True, "false_positive": True}
    assert score_for_interface("rl.mcp.vulnerability_defense.v1", caps) == 0.0


def test_defensive_infra_failure_nullifies_score():
    caps = {"patch_format_valid": True, "infrastructure_failure": True}
    assert compute_defensive_score(caps) == 0.0


def test_defensive_partial_credit_is_monotonic():
    low = compute_defensive_score({"patch_format_valid": True})
    mid = compute_defensive_score({"patch_format_valid": True,
                                   "baseline_reproduced": True,
                                   "candidate_build_passed": True})
    assert 0 < low < mid < defensive_policy_max()


def test_regression_pass_is_weighted_heaviest():
    w = DEFENSIVE_SCORING_POLICY["weights"]
    assert w["regression_test_passed"] == max(w.values())
