"""Provenance primitives: evidence references with content hashes + times.

Every authoritative fact used to build a task carries an EvidenceRef: where
it came from, when it was retrieved, and a content hash of the exact bytes
relied upon. This is what lets a task be independently re-verified and what
keeps the ingestion layer honest — a claim with no evidence is not a fact.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="surrogatepass"))


@dataclass(frozen=True)
class EvidenceRef:
    """One provenance record. `kind` is a coarse source type."""

    kind: str                       # 'cve_record'|'nvd'|'chromium_issue'|'commit'|'advisory'|'fixture'
    source: str                     # URL or local reference
    retrieved_at: str = field(default_factory=utc_now_iso)
    content_sha256: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "source": self.source,
            "retrieved_at": self.retrieved_at,
            "content_sha256": self.content_sha256,
            "note": self.note,
        }

    @classmethod
    def for_content(
        cls, *, kind: str, source: str, content: bytes | str, note: str | None = None
    ) -> EvidenceRef:
        """Build an EvidenceRef, hashing `content` for integrity."""
        digest = sha256_text(content) if isinstance(content, str) else sha256_bytes(content)
        return cls(kind=kind, source=source, content_sha256=digest, note=note)


@dataclass
class PatchProvenance:
    """Tracks how (and whether) a fixing patch's authenticity is established.

    `verified` requires an authoritative source AND a content hash — never a
    bare advisory link. The task spec is explicit: do not mark a patch verified
    simply because it is linked from an advisory.
    """

    status: str = "unknown"         # 'verified'|'claimed'|'unknown'|'absent'
    source: str | None = None
    content_sha256: str | None = None
    retrieved_at: str | None = None
    note: str | None = None

    def mark_claimed(self, source: str, note: str | None = None) -> None:
        self.status = "claimed"
        self.source = source
        self.retrieved_at = utc_now_iso()
        self.note = note

    def mark_verified(self, source: str, content: bytes | str, note: str | None = None) -> None:
        self.status = "verified"
        self.source = source
        self.content_sha256 = (
            sha256_text(content) if isinstance(content, str) else sha256_bytes(content)
        )
        self.retrieved_at = utc_now_iso()
        self.note = note

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "source": self.source,
            "content_sha256": self.content_sha256,
            "retrieved_at": self.retrieved_at,
            "note": self.note,
        }
