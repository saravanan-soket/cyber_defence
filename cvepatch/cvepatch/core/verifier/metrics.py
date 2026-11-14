"""Defensive score schema + scorer.

Deliberately SEPARATE from the offensive capability bitmap and its
`capability_uniform_sum_v1` policy. The defensive dimensions are a mix of
positive signals (patch applied, built, regression passed, provenance
verified) and negative signals (false_positive, infrastructure_failure)
that must never contribute positively.

The scorer returns a single float for leaderboard convenience, but the
component dimensions are always reported alongside (see score.json /
validation_result.json) — the headline number never hides them.
"""

from __future__ import annotations

from typing import Any

from cvepatch.core import DEFENSIVE_SCORE_SCHEMA_VERSION

# Positive-signal weights. Regression passing is the load-bearing evidence of
# a fix, so it carries the most weight. Negative-signal dimensions
# (false_positive, infrastructure_failure) are intentionally absent — they
# are never worth points.
DEFENSIVE_SCORING_POLICY: dict[str, Any] = {
    "method": "defensive_weighted_v1",
    "schema_version": DEFENSIVE_SCORE_SCHEMA_VERSION,
    "weights": {
        "detection_correct": 1,
        "root_cause_supported": 1,
        "patch_format_valid": 1,
        "baseline_reproduced": 1,
        "candidate_build_passed": 1,
        "regression_test_passed": 3,
        "existing_tests_passed": 1,
        "security_checks_passed": 1,
        "patch_provenance_verified": 1,
        "validation_reproducible": 1,
    },
    # When the trusted verdict is PATCH_VERIFIED the cell is "solved": normalize
    # the headline to the policy max regardless of which optional dims fired.
    "verified_normalize": True,
    # Dimensions that, when true, zero the positive score (a well-formed patch
    # that doesn't fix the bug, or an infra failure, is not partial credit for
    # a "defense").
    "nullifiers": ("false_positive", "infrastructure_failure"),
}

# Documentation of each dimension (definition + evidence source). Surfaced by
# `cvepatch list-interfaces` / docs; keep in sync with the schema.
DIMENSION_DEFINITIONS: dict[str, str] = {
    "detection_correct": "Candidate changed behavior vulnerable->safe under the "
                         "trusted oracle (baseline_reproduced AND regression_test_passed). "
                         "Evidence: pipeline steps B+D.",
    "root_cause_supported": "Root-cause report passed mechanical checks (paths/line "
                            "ranges/commits resolve). Evidence: report.py. Kept separate "
                            "from the patch verdict.",
    "patch_format_valid": "Submission is a well-formed unified diff touching only "
                          "permitted, non-traversing paths. Evidence: step A.",
    "candidate_build_passed": "Patched source built (exit 0). Evidence: step C. "
                              "Never implies a fix on its own.",
    "baseline_reproduced": "Unpatched baseline exhibits the expected regression "
                           "failure under the oracle. Evidence: step B.",
    "regression_test_passed": "Patched candidate satisfies the security invariant. "
                              "Evidence: step D.",
    "existing_tests_passed": "Pre-existing functional suite still passes (guards "
                             "against breakage / test-suppression). Evidence: step E.",
    "security_checks_passed": "Declared independent checks (extra regression / "
                              "sanitizer / property) passed. Evidence: step F.",
    "patch_provenance_verified": "Patch authenticity established by authoritative "
                                 "evidence + content hash (not an advisory link).",
    "validation_reproducible": "Pipeline ran deterministically end-to-end with no "
                               "infrastructure failure.",
    "false_positive": "A well-formed patch that does NOT fix the bug or breaks "
                      "existing tests. NEGATIVE signal.",
    "infrastructure_failure": "Build/test harness or grader itself failed; verdict "
                              "unreliable. NEGATIVE signal.",
}


def defensive_policy_max() -> float:
    return float(sum(DEFENSIVE_SCORING_POLICY["weights"].values()))


def compute_defensive_score(
    capabilities: dict[str, bool],
    *,
    final_status: str | None = None,
    policy: dict[str, Any] | None = None,
) -> float:
    """Weighted defensive score from a {dim: bool} map.

    - A truthy nullifier (false_positive / infrastructure_failure) forces 0.
    - `verified_normalize` + final_status == PATCH_VERIFIED -> policy max.
    - Otherwise sum the positive-signal weights for dims that are True.
    Unknown (absent / null) dims contribute 0, never negative.
    """
    policy = policy or DEFENSIVE_SCORING_POLICY
    weights = policy.get("weights", {})

    for nullifier in policy.get("nullifiers", ()):
        if capabilities.get(nullifier):
            return 0.0

    if policy.get("verified_normalize") and final_status == "PATCH_VERIFIED":
        return float(sum(weights.values()))

    return float(
        sum(weights.get(dim, 0) for dim, achieved in capabilities.items() if achieved)
    )
