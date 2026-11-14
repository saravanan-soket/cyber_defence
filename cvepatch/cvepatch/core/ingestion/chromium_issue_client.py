"""Chromium issue metadata client + Chrome-vs-V8 attribution.

Chromium issues are frequently access-restricted (security bugs stay private
for months). This client normalizes issue ids, records provenance, and
explicitly represents the inaccessible case rather than guessing. It does
NOT claim a bug affects V8 from the issue text alone — `affects_v8_candidate`
is a candidate flag, to be confirmed later by commit/path evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.ingestion.cve_client import Fetcher, _default_fetcher
from cvepatch.core.ingestion.identifiers import affects_v8, normalize_crbug
from cvepatch.core.ingestion.provenance import EvidenceRef


@dataclass
class ChromiumIssueRecord:
    issue_id: str                       # canonical 'crbug-NNNN'
    accessible: bool
    component: str | None
    summary: str | None
    affects_v8_candidate: bool
    source_url: str
    evidence: EvidenceRef | None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "issue_id": self.issue_id,
            "accessible": self.accessible,
            "component": self.component,
            "summary": self.summary,
            "affects_v8_candidate": self.affects_v8_candidate,
            "source_url": self.source_url,
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }


@dataclass
class ChromiumIssueClient:
    """Resolve Chromium issue metadata. Local-record first; network optional."""

    cache_dir: Path
    fetcher: Fetcher = _default_fetcher

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def from_local(self, record: dict[str, Any]) -> ChromiumIssueRecord:
        """Build a record from a locally-provided metadata dict (no network).

        This is the primary path: security issues are usually resolved from a
        curated local snapshot rather than a live, access-controlled tracker.
        """
        issue_id = normalize_crbug(str(record.get("issue_id") or record.get("id") or ""))
        component = record.get("component")
        summary = record.get("summary")
        accessible = bool(record.get("accessible", True))
        source = record.get("source") or f"local:{issue_id}"
        ev = None
        if accessible:
            ev = EvidenceRef(kind="chromium_issue", source=source,
                             note=record.get("note"))
        return ChromiumIssueRecord(
            issue_id=issue_id,
            accessible=accessible,
            component=component,
            summary=summary,
            affects_v8_candidate=accessible and affects_v8(component, summary),
            source_url=source,
            evidence=ev,
            raw=record,
        )

    def mark_inaccessible(self, issue_like: str, *, note: str | None = None) -> ChromiumIssueRecord:
        """Represent an issue we could not read (private / deleted) explicitly."""
        issue_id = normalize_crbug(issue_like)
        return ChromiumIssueRecord(
            issue_id=issue_id,
            accessible=False,
            component=None,
            summary=None,
            affects_v8_candidate=False,
            source_url=f"inaccessible:{issue_id}",
            evidence=None,
            raw={"note": note or "issue not accessible"},
        )
