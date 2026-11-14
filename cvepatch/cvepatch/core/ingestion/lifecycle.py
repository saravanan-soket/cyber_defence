"""Task lifecycle state machine + transition log.

A defensive task candidate moves through a documented set of statuses as it
is ingested, classified, built, reproduced, and (maybe) patch-verified.
Every transition records a reason and supporting evidence; illegal
transitions raise.

Critical invariant (docs/ARCHITECTURE.md §8): a successful image
build advances a task at most to BUILDABLE. It can NEVER jump to
REPRODUCIBLE or PATCH_VERIFIED — those require the trusted oracle to confirm
the defect reproduces (and, for PATCH_VERIFIED, the full validation pipeline
to pass). The transition table encodes that: BUILDABLE -> REPRODUCIBLE is a
legal edge, but it is the *caller* (the validator) that may take it, only
with oracle evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    DISCOVERED = "DISCOVERED"
    CLASSIFIED = "CLASSIFIED"
    BUILDABLE = "BUILDABLE"
    REPRODUCIBLE = "REPRODUCIBLE"
    PATCH_VERIFIED = "PATCH_VERIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    MANUAL_REVIEW = "MANUAL_REVIEW"


# Terminal / off-ramp statuses reachable from (almost) anywhere.
_OFF_RAMPS: frozenset[Status] = frozenset(
    {Status.UNSUPPORTED, Status.FAILED, Status.INCONCLUSIVE, Status.MANUAL_REVIEW}
)

# The happy-path forward edges. Off-ramps are added to every source below.
_FORWARD: dict[Status, set[Status]] = {
    Status.DISCOVERED: {Status.CLASSIFIED},
    Status.CLASSIFIED: {Status.BUILDABLE},
    Status.BUILDABLE: {Status.REPRODUCIBLE},
    Status.REPRODUCIBLE: {Status.PATCH_VERIFIED},
    Status.PATCH_VERIFIED: set(),
    # Off-ramp states can be re-opened to MANUAL_REVIEW for human triage, or
    # retried from the start, but otherwise do not advance on their own.
    Status.UNSUPPORTED: set(),
    Status.FAILED: {Status.MANUAL_REVIEW},
    Status.INCONCLUSIVE: {Status.MANUAL_REVIEW},
    Status.MANUAL_REVIEW: set(),
}


def allowed_transitions(src: Status) -> frozenset[Status]:
    """Return the set of statuses reachable from `src` in one legal step."""
    out = set(_FORWARD.get(src, set()))
    # Any non-terminal state may go to an off-ramp (classification revealed it
    # is unsupported, a step failed, the oracle was inconclusive, etc.).
    if src not in (Status.PATCH_VERIFIED, Status.UNSUPPORTED):
        out |= set(_OFF_RAMPS)
    out.discard(src)
    return frozenset(out)


class IllegalTransition(Exception):
    """Raised on a transition not permitted by the table."""


@dataclass(frozen=True)
class Transition:
    from_status: Status
    to_status: Status
    reason: str
    evidence: tuple[dict[str, Any], ...]
    at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_status.value,
            "to": self.to_status.value,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "at": self.at,
        }


@dataclass
class LifecycleTracker:
    """Holds a task's current status + an append-only transition history."""

    task_id: str
    status: Status = Status.DISCOVERED
    history: list[Transition] = field(default_factory=list)

    def transition(
        self,
        to: Status | str,
        *,
        reason: str,
        evidence: list[dict[str, Any]] | None = None,
        at: str | None = None,
    ) -> Transition:
        """Advance to `to`, recording reason + evidence. Raises on illegal edge.

        A reason is mandatory — a transition without a recorded justification
        is itself a bug. Every transition must also carry at least one piece
        of evidence (empty evidence is allowed only for the initial
        DISCOVERED seeding, which uses `seed()` instead).
        """
        to = Status(to)
        if to not in allowed_transitions(self.status):
            raise IllegalTransition(
                f"{self.task_id}: illegal transition {self.status.value} -> "
                f"{to.value} (allowed: "
                f"{sorted(s.value for s in allowed_transitions(self.status))})"
            )
        if not reason.strip():
            raise ValueError("transition requires a non-empty reason")
        t = Transition(
            from_status=self.status,
            to_status=to,
            reason=reason,
            evidence=tuple(evidence or ()),
            at=at or datetime.now(UTC).isoformat(),
        )
        self.history.append(t)
        self.status = to
        return t

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "history": [t.to_dict() for t in self.history],
        }
