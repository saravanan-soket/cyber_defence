"""Interface-aware scoring dispatch.

The orchestrator computes `runs.score` from the post-episode capability
bitmap. Historically this was a single hardcoded call to
`capabilities.compute_score(..., DEFAULT_SCORING_POLICY)` — the offensive
`capability_uniform_sum_v1` policy.

Defensive tasks must NOT be scored by the offensive capability sum (their
bitmap is a disjoint set of defensive dimensions). This module selects the
right scorer by interface name, keeping offensive behavior byte-for-byte
identical:

  * offensive / unknown interfaces -> capabilities.compute_score (unchanged)
  * rl.mcp.vulnerability_defense.v1 -> defensive weighted score

Isolating the dispatch here keeps `orchestrator.py`'s change to a single
call site and makes the policy-selection rule unit-testable without Docker.
"""

from __future__ import annotations

from typing import Any

from cvepatch.core import DEFENSIVE_INTERFACE
from cvepatch.runner.capabilities import DEFAULT_SCORING_POLICY, compute_score


def score_for_interface(
    interface: str | None,
    capabilities: dict[str, bool],
    *,
    final_status: str | None = None,
    offensive_policy: dict[str, Any] | None = None,
) -> float:
    """Return `runs.score` for a capability bitmap, chosen by interface.

    `final_status` is only consulted for the defensive interface (to let a
    PATCH_VERIFIED verdict normalize to the policy max). For every offensive
    interface the behavior is exactly `compute_score(capabilities, policy)`.
    """
    if interface == DEFENSIVE_INTERFACE:
        # Local import to avoid pulling the defensive package into the hot
        # offensive path at module import time.
        from cvepatch.core.verifier.metrics import compute_defensive_score

        return compute_defensive_score(capabilities, final_status=final_status)

    return compute_score(capabilities, offensive_policy or DEFAULT_SCORING_POLICY)
