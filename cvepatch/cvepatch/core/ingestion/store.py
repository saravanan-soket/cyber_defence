"""Candidate ingestion + deduplication store.

Accepts the identifier/manifest shapes the task spec lists:
  * CVE ids               -> ingest_cve
  * Chromium issue ids    -> ingest_chromium_issue
  * local JSON / JSONL    -> ingest_jsonl / ingest_json_record
  * explicit repo+commit  -> ingest_source_ref

Normalizes identifiers, deduplicates by canonical key, preserves provenance
on every record, distinguishes Chrome-vs-V8, and seeds a lifecycle tracker at
DISCOVERED (advancing to CLASSIFIED once attribution + evidence exist). It
does NOT build images or claim reproducibility — that is downstream work.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.ingestion.identifiers import (
    IdentifierError,
    NormalizedId,
    affects_v8,
    normalize_any,
    normalize_commit,
    normalize_crbug,
    normalize_cve,
)
from cvepatch.core.ingestion.lifecycle import LifecycleTracker, Status
from cvepatch.core.ingestion.provenance import EvidenceRef, PatchProvenance


@dataclass
class Candidate:
    """A deduplicated vulnerability candidate accumulated during ingestion."""

    key: str                                   # canonical dedup key
    identifiers: dict[str, str] = field(default_factory=dict)  # kind -> value
    product: str | None = None
    component: str | None = None
    summary: str | None = None
    affects_v8_candidate: bool = False
    source_repository: str | None = None
    vulnerable_commit: str | None = None
    fixed_commit: str | None = None
    evidence: list[EvidenceRef] = field(default_factory=list)
    patch_provenance: PatchProvenance = field(default_factory=PatchProvenance)
    lifecycle: LifecycleTracker | None = None

    def add_evidence(self, ev: EvidenceRef) -> None:
        # Dedup identical evidence (same kind+source+hash).
        sig = (ev.kind, ev.source, ev.content_sha256)
        for e in self.evidence:
            if (e.kind, e.source, e.content_sha256) == sig:
                return
        self.evidence.append(ev)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "identifiers": dict(self.identifiers),
            "product": self.product,
            "component": self.component,
            "summary": self.summary,
            "affects_v8_candidate": self.affects_v8_candidate,
            "source_repository": self.source_repository,
            "vulnerable_commit": self.vulnerable_commit,
            "fixed_commit": self.fixed_commit,
            "evidence": [e.to_dict() for e in self.evidence],
            "patch_provenance": self.patch_provenance.to_dict(),
            "status": self.lifecycle.status.value if self.lifecycle else Status.DISCOVERED.value,
            "lifecycle": self.lifecycle.to_dict() if self.lifecycle else None,
        }


class CandidateStore:
    """Holds candidates keyed by a canonical dedup key; merges on re-ingest."""

    def __init__(self) -> None:
        self._by_key: dict[str, Candidate] = {}
        # Secondary index: any identifier value -> primary key, so a record
        # seen first by crbug and later by CVE merges into one candidate.
        self._alias: dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._by_key)

    def all(self) -> list[Candidate]:
        return list(self._by_key.values())

    def get(self, key: str) -> Candidate | None:
        return self._by_key.get(self._alias.get(key, key))

    # -- internal: find-or-create a candidate given a set of normalized ids --
    def _resolve(self, ids: list[NormalizedId]) -> Candidate:
        # Reuse an existing candidate if any identifier already maps to one.
        existing_key: str | None = None
        for nid in ids:
            k = self._alias.get(nid.dedup_key)
            if k is not None:
                existing_key = k
                break
        if existing_key is None:
            existing_key = ids[0].dedup_key
            if existing_key not in self._by_key:
                cand = Candidate(key=existing_key)
                cand.lifecycle = LifecycleTracker(task_id=existing_key)
                self._by_key[existing_key] = cand
        cand = self._by_key[existing_key]
        for nid in ids:
            cand.identifiers.setdefault(nid.kind, nid.value)
            self._alias[nid.dedup_key] = existing_key
        return cand

    def _maybe_classify(self, cand: Candidate) -> None:
        """Advance DISCOVERED -> CLASSIFIED once we have evidence + attribution."""
        if cand.lifecycle and cand.lifecycle.status == Status.DISCOVERED and cand.evidence:
            cand.lifecycle.transition(
                Status.CLASSIFIED,
                reason="normalized identifiers + provenance recorded",
                evidence=[e.to_dict() for e in cand.evidence[:1]],
            )

    # ---------------------------- ingest APIs -----------------------------

    def ingest_cve(self, record: Any) -> Candidate:
        """Ingest a CveRecord (from cve_client) or a dict with cve fields."""
        if hasattr(record, "to_dict"):
            d = record.to_dict()
            ev = record.evidence
        else:
            d = dict(record)
            ev = EvidenceRef(kind="cve_record", source=d.get("source_url", "local"))
        cve_id = normalize_cve(d["cve_id"])
        cand = self._resolve([NormalizedId("cve", cve_id)])
        cand.summary = cand.summary or d.get("description")
        cand.component = cand.component or d.get("component")
        if d.get("affects_v8_candidate") or affects_v8(cand.component, cand.summary):
            cand.affects_v8_candidate = True
        cand.add_evidence(ev)
        self._maybe_classify(cand)
        return cand

    def ingest_chromium_issue(self, record: Any) -> Candidate:
        """Ingest a ChromiumIssueRecord or dict."""
        d = record.to_dict() if hasattr(record, "to_dict") else dict(record)
        cand = self._resolve([NormalizedId("crbug", normalize_crbug(str(d["issue_id"])))])
        cand.component = cand.component or d.get("component")
        cand.summary = cand.summary or d.get("summary")
        if d.get("affects_v8_candidate"):
            cand.affects_v8_candidate = True
        if d.get("evidence"):
            e = d["evidence"]
            cand.add_evidence(EvidenceRef(kind=e["kind"], source=e["source"],
                                          retrieved_at=e.get("retrieved_at"),
                                          content_sha256=e.get("content_sha256"),
                                          note=e.get("note")))
        self._maybe_classify(cand)
        return cand

    def ingest_source_ref(
        self, *, repository: str, vulnerable_commit: str,
        fixed_commit: str | None = None, cve_id: str | None = None,
        chromium_issue_id: str | None = None, note: str | None = None,
    ) -> Candidate:
        """Ingest an explicit source repository + commit reference."""
        ids: list[NormalizedId] = []
        if cve_id:
            ids.append(NormalizedId("cve", normalize_cve(cve_id)))
        if chromium_issue_id:
            ids.append(normalize_any(chromium_issue_id))
        vuln = normalize_commit(vulnerable_commit) if _looks_hex(vulnerable_commit) else vulnerable_commit
        if not ids:
            ids.append(NormalizedId("commit", vuln if _looks_hex(vulnerable_commit) else vulnerable_commit))
        cand = self._resolve(ids)
        cand.source_repository = repository
        cand.vulnerable_commit = vuln
        if fixed_commit:
            cand.fixed_commit = normalize_commit(fixed_commit) if _looks_hex(fixed_commit) else fixed_commit
        cand.add_evidence(EvidenceRef(kind="commit", source=f"{repository}@{vuln}", note=note))
        self._maybe_classify(cand)
        return cand

    def ingest_json_record(self, record: dict[str, Any]) -> Candidate:
        """Ingest one local manifest record (flexible shape)."""
        ids: list[NormalizedId] = []
        for field_name in ("cve_id", "cve"):
            if record.get(field_name):
                with contextlib.suppress(IdentifierError):
                    ids.append(NormalizedId("cve", normalize_cve(record[field_name])))
        for field_name in ("chromium_issue_id", "crbug", "issue_id"):
            if record.get(field_name):
                with contextlib.suppress(IdentifierError):
                    ids.append(normalize_any(str(record[field_name])))
        if not ids and record.get("vulnerable_commit"):
            return self.ingest_source_ref(
                repository=record.get("source_repository", "unknown"),
                vulnerable_commit=record["vulnerable_commit"],
                fixed_commit=record.get("fixed_commit"),
            )
        if not ids:
            raise IdentifierError(f"record has no usable identifier: {record}")
        cand = self._resolve(ids)
        cand.product = cand.product or record.get("product")
        cand.component = cand.component or record.get("component")
        cand.summary = cand.summary or record.get("summary") or record.get("description")
        cand.source_repository = cand.source_repository or record.get("source_repository")
        if record.get("vulnerable_commit"):
            cand.vulnerable_commit = cand.vulnerable_commit or record["vulnerable_commit"]
        if record.get("fixed_commit"):
            cand.fixed_commit = cand.fixed_commit or record["fixed_commit"]
        if record.get("affects_v8") or affects_v8(cand.component, cand.summary):
            cand.affects_v8_candidate = True
        cand.add_evidence(EvidenceRef(
            kind="local_manifest", source=record.get("source", "local-jsonl"),
            note=record.get("note")))
        self._maybe_classify(cand)
        return cand

    def ingest_jsonl(self, path: str | Path) -> list[Candidate]:
        """Ingest a JSONL (or JSON array) local manifest file."""
        text = Path(path).read_text(encoding="utf-8")
        out: list[Candidate] = []
        stripped = text.lstrip()
        if stripped.startswith("["):
            for rec in json.loads(text):
                out.append(self.ingest_json_record(rec))
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                out.append(self.ingest_json_record(json.loads(line)))
        return out

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(c.to_dict()) for c in self._by_key.values())


def _looks_hex(s: str) -> bool:
    s = s.strip().lower()
    return len(s) >= 7 and all(c in "0123456789abcdef" for c in s)
