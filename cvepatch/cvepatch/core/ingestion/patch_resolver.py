"""Verify a fixing patch only when authoritative content supports it.

Given a candidate commit (from `advisory_resolver`) and the actual patch
content (fetched from the authoritative source, or supplied locally), this
module confirms the patch and records a content hash. Without content, the
patch stays `claimed` / `unknown` — never `verified`.

It deliberately does NOT trust third-party patch content on its face: the
caller provides the authoritative bytes, and the resolver hashes exactly
those bytes so the task manifest's provenance is reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass

from cvepatch.core.ingestion.advisory_resolver import CandidateCommit
from cvepatch.core.ingestion.identifiers import normalize_commit
from cvepatch.core.ingestion.provenance import PatchProvenance


@dataclass
class ResolvedPatch:
    commit: str | None
    provenance: PatchProvenance

    def to_dict(self) -> dict:
        return {"commit": self.commit, "provenance": self.provenance.to_dict()}


def mark_absent(note: str = "no fixing patch is known") -> ResolvedPatch:
    """Explicitly represent 'there is no known fix' — not an error, a fact."""
    prov = PatchProvenance(status="absent", note=note)
    return ResolvedPatch(commit=None, provenance=prov)


def mark_claimed(candidate: CandidateCommit) -> ResolvedPatch:
    """Record an advisory-linked candidate as CLAIMED (not verified)."""
    prov = PatchProvenance()
    prov.mark_claimed(source=candidate.source_url,
                      note="advisory-linked candidate; content not yet confirmed")
    return ResolvedPatch(commit=candidate.sha.lower(), provenance=prov)


def verify_with_content(
    commit: str,
    *,
    authoritative_source: str,
    patch_content: bytes | str,
    note: str | None = None,
) -> ResolvedPatch:
    """Promote a commit to VERIFIED, hashing the authoritative patch bytes.

    The caller is responsible for having fetched `patch_content` from an
    authoritative source (the resolver hashes exactly those bytes). This is
    the only path that yields status='verified'.
    """
    sha = normalize_commit(commit)
    prov = PatchProvenance()
    prov.mark_verified(source=authoritative_source, content=patch_content, note=note)
    return ResolvedPatch(commit=sha, provenance=prov)
