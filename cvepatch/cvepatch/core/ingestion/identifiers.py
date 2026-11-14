"""Vulnerability identifier normalization + classification helpers.

Normalizes the identifier shapes the ingestion layer accepts (CVE, NVD,
Chromium issue / crbug, GHSA, raw commit refs) into canonical forms so
records deduplicate reliably. Also distinguishes Chrome-wide vulnerabilities
from those specifically affecting V8.

Pure string logic — no network. Resolution of an identifier to actual
commits/advisories lives in the client modules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_CVE_RE = re.compile(r"(?i)\bCVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})\b")
_GHSA_RE = re.compile(r"(?i)\bGHSA-([a-z0-9]{4})-([a-z0-9]{4})-([a-z0-9]{4})\b")
# Chromium issue trackers: legacy "crbug.com/NNNN" / "issue NNNN" and the
# monorail/issuetracker numeric ids.
_CRBUG_RE = re.compile(r"(?i)\b(?:crbug(?:\.com)?[/: ]|issue[ #:]*|chromium[-_ ]?)?(\d{3,10})\b")
_COMMIT_RE = re.compile(r"\b([0-9a-f]{7,40})\b")


class IdentifierError(ValueError):
    """Raised when a string cannot be parsed as the requested identifier."""


def normalize_cve(raw: str) -> str:
    """Return canonical 'CVE-YYYY-NNNN' or raise IdentifierError."""
    m = _CVE_RE.search(raw or "")
    if not m:
        raise IdentifierError(f"not a CVE id: {raw!r}")
    return f"CVE-{m.group(1)}-{m.group(2)}"


def normalize_ghsa(raw: str) -> str:
    m = _GHSA_RE.search(raw or "")
    if not m:
        raise IdentifierError(f"not a GHSA id: {raw!r}")
    return "GHSA-" + "-".join(m.groups()).lower()


def normalize_crbug(raw: str) -> str:
    """Return canonical 'crbug-NNNN' from a Chromium issue reference."""
    s = (raw or "").strip()
    m = _CRBUG_RE.search(s)
    if not m:
        raise IdentifierError(f"not a Chromium issue id: {raw!r}")
    return f"crbug-{m.group(1)}"


def normalize_commit(raw: str) -> str:
    """Return a lowercased commit hash (7-40 hex) or raise."""
    s = (raw or "").strip().lower()
    m = _COMMIT_RE.fullmatch(s) or _COMMIT_RE.search(s)
    if not m:
        raise IdentifierError(f"not a commit hash: {raw!r}")
    return m.group(1)


@dataclass(frozen=True)
class NormalizedId:
    kind: str          # 'cve' | 'ghsa' | 'crbug' | 'commit'
    value: str         # canonical form

    @property
    def dedup_key(self) -> str:
        return f"{self.kind}:{self.value}"


def normalize_any(raw: str) -> NormalizedId:
    """Best-effort: detect and normalize whichever identifier `raw` looks like.

    Order matters — CVE/GHSA are checked before the broad crbug/commit
    numeric/hex patterns so a 'CVE-2024-1234' is not mis-read as a bare
    number or hex run.
    """
    for kind, fn in (("cve", normalize_cve), ("ghsa", normalize_ghsa)):
        try:
            return NormalizedId(kind, fn(raw))
        except IdentifierError:
            pass
    # crbug before commit: a pure numeric id is an issue, not a commit.
    s = (raw or "").strip()
    if re.fullmatch(r"\d{3,10}", s) or re.search(r"(?i)crbug|issue|chromium", s):
        try:
            return NormalizedId("crbug", normalize_crbug(raw))
        except IdentifierError:
            pass
    try:
        return NormalizedId("commit", normalize_commit(raw))
    except IdentifierError:
        pass
    raise IdentifierError(f"unrecognized identifier: {raw!r}")


# ---------------------------------------------------------------------------
# Chrome-vs-V8 attribution
# ---------------------------------------------------------------------------

# Substrings in advisory/component text that indicate the bug is specifically
# in V8 (the JS engine) rather than Chrome at large.
_V8_MARKERS = (
    "v8", "javascript engine", "js engine", "turbofan", "maglev", "sparkplug",
    "ignition", "wasm", "webassembly", "liftoff",
)
_NON_V8_COMPONENT_HINTS = (
    "blink", "skia", "pdfium", "angle", "webrtc", "ui", "extensions",
    "network", "media", "gpu",
)


def affects_v8(component: str | None, summary: str | None = None) -> bool:
    """Heuristic: does this record specifically affect V8?

    Conservative — returns True only when a V8 marker is present AND no
    stronger non-V8 component hint dominates. Callers should treat this as a
    classification *candidate*, confirmed later by commit/path evidence, never
    as proof (the task spec forbids trusting a description alone).
    """
    text = f"{component or ''} {summary or ''}".lower()
    if not any(m in text for m in _V8_MARKERS):
        return False
    comp = (component or "").lower()
    # If the component field names a clearly non-V8 subsystem, defer to it.
    return not (any(h in comp for h in _NON_V8_COMPONENT_HINTS) and "v8" not in comp)
