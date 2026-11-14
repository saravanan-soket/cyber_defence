"""Resolve advisories/references to CANDIDATE fixing commits — evidence only.

The hard rule (task spec): a commit linked from an advisory is a *candidate*,
not a verified fix. This resolver extracts candidate commit references from
advisory/reference URLs and records where each came from, but never promotes
one to 'verified'. Verification is `patch_resolver`'s job, and only with
authoritative content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from cvepatch.core.ingestion.provenance import EvidenceRef

# Common commit-bearing URL shapes (chromium googlesource, github, gitiles).
_COMMIT_URL_RES = (
    re.compile(r"(?i)chromium\.googlesource\.com/.+/\+/(?P<sha>[0-9a-f]{7,40})"),
    re.compile(r"(?i)github\.com/.+/commit/(?P<sha>[0-9a-f]{7,40})"),
    re.compile(r"(?i)/\+/(?P<sha>[0-9a-f]{7,40})\b"),
    re.compile(r"(?i)[?&]id=(?P<sha>[0-9a-f]{7,40})"),
)


@dataclass
class CandidateCommit:
    sha: str
    source_url: str
    evidence: EvidenceRef
    confidence: str = "candidate"   # always 'candidate' here; never 'verified'

    def to_dict(self) -> dict:
        return {
            "sha": self.sha,
            "source_url": self.source_url,
            "confidence": self.confidence,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class AdvisoryResolution:
    references: tuple[str, ...]
    candidate_commits: tuple[CandidateCommit, ...] = field(default_factory=tuple)
    unresolved: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "references": list(self.references),
            "candidate_commits": [c.to_dict() for c in self.candidate_commits],
            "unresolved": list(self.unresolved),
        }


def resolve_candidate_commits(references: list[str] | tuple[str, ...]) -> AdvisoryResolution:
    """Extract candidate fixing commits from advisory/reference URLs.

    De-duplicates by sha. Every candidate carries the URL it came from as
    evidence. Nothing here is treated as a verified fix.
    """
    seen: dict[str, CandidateCommit] = {}
    unresolved: list[str] = []
    for url in references:
        matched = False
        for rx in _COMMIT_URL_RES:
            m = rx.search(url or "")
            if m:
                sha = m.group("sha").lower()
                matched = True
                if sha not in seen:
                    seen[sha] = CandidateCommit(
                        sha=sha,
                        source_url=url,
                        evidence=EvidenceRef(kind="advisory", source=url,
                                             note="candidate fixing commit (unverified)"),
                    )
                break
        if not matched:
            unresolved.append(url)
    return AdvisoryResolution(
        references=tuple(references),
        candidate_commits=tuple(seen.values()),
        unresolved=tuple(unresolved),
    )
