"""Lifecycle state machine (spec §6 statuses, §8 invariants)."""

from __future__ import annotations

import pytest

from cvepatch.core.ingestion.lifecycle import (
    IllegalTransition,
    LifecycleTracker,
    Status,
    allowed_transitions,
)


def test_happy_path_transitions():
    t = LifecycleTracker("task-1")
    t.transition(Status.CLASSIFIED, reason="normalized", evidence=[{"k": "v"}])
    t.transition(Status.BUILDABLE, reason="built", evidence=[{"k": "v"}])
    t.transition(Status.REPRODUCIBLE, reason="oracle confirmed", evidence=[{"k": "v"}])
    t.transition(Status.PATCH_VERIFIED, reason="validated", evidence=[{"k": "v"}])
    assert t.status == Status.PATCH_VERIFIED
    assert len(t.history) == 4


def test_build_cannot_jump_to_reproducible_or_verified():
    # The critical invariant: a build only reaches BUILDABLE. Skipping straight
    # from CLASSIFIED to REPRODUCIBLE/PATCH_VERIFIED is illegal.
    t = LifecycleTracker("task-2")
    t.transition(Status.CLASSIFIED, reason="x", evidence=[{"k": "v"}])
    with pytest.raises(IllegalTransition):
        t.transition(Status.REPRODUCIBLE, reason="should fail", evidence=[{"k": "v"}])
    with pytest.raises(IllegalTransition):
        t.transition(Status.PATCH_VERIFIED, reason="should fail", evidence=[{"k": "v"}])


def test_buildable_to_verified_directly_is_illegal():
    t = LifecycleTracker("task-3")
    t.transition(Status.CLASSIFIED, reason="x", evidence=[{"k": "v"}])
    t.transition(Status.BUILDABLE, reason="image built", evidence=[{"k": "v"}])
    # BUILDABLE -> PATCH_VERIFIED must go through REPRODUCIBLE.
    with pytest.raises(IllegalTransition):
        t.transition(Status.PATCH_VERIFIED, reason="no repro step", evidence=[{"k": "v"}])


def test_off_ramps_reachable():
    assert Status.INCONCLUSIVE in allowed_transitions(Status.BUILDABLE)
    assert Status.MANUAL_REVIEW in allowed_transitions(Status.REPRODUCIBLE)
    assert Status.FAILED in allowed_transitions(Status.CLASSIFIED)


def test_transition_requires_reason():
    t = LifecycleTracker("task-4")
    with pytest.raises(ValueError):
        t.transition(Status.CLASSIFIED, reason="  ", evidence=[{"k": "v"}])


def test_verified_is_terminal():
    assert allowed_transitions(Status.PATCH_VERIFIED) == frozenset()
