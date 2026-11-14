"""The agent-facing advisory for a CVE: what a defender would read first.

Built from a CVE JSON 5 record. Deliberately keeps only the description,
CWE ids, affected products/versions and dates. Reference URLs are dropped
because they usually include the fix commit, which must stay hidden from
the agent (it is the verifier's reference, not a hint).
"""

from __future__ import annotations

import re
from typing import Any

# Some CNAs put the fixing commit in the description ("Patch name: <sha>").
_COMMIT_URL_RE = re.compile(r"https?://\S*/commits?/[0-9a-fA-F]{7,40}\S*")
_SHA_RE = re.compile(r"\b[0-9a-fA-F]{12,40}\b")


def scrub(text: str | None) -> str | None:
    """Remove commit hashes / commit URLs (they identify the hidden fix)."""
    if not text:
        return text
    return _SHA_RE.sub("<commit>", _COMMIT_URL_RE.sub("<commit-url>", text))


def scrub_advisory(adv: dict | None) -> dict | None:
    """Deep-scrub every string in an advisory (descriptions, titles, and
    affected-version strings can all carry the fixing commit sha)."""
    if not adv:
        return adv

    def walk(o):
        if isinstance(o, str):
            return scrub(o)
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o

    return walk(adv)


def _english(items: list[dict[str, Any]] | None) -> str:
    items = items or []
    for d in items:
        if str(d.get("lang", "")).lower().startswith("en") and d.get("value"):
            return str(d["value"]).strip()
    return str(items[0].get("value", "")).strip() if items else ""


def advisory_from_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """CVE JSON 5 record -> advisory dict, or None if it isn't a usable record."""
    meta = rec.get("cveMetadata") or {}
    cve_id = meta.get("cveId")
    if not cve_id or meta.get("state") != "PUBLISHED":
        return None
    cna = (rec.get("containers") or {}).get("cna") or {}
    cwes: list[str] = []
    for pt in cna.get("problemTypes") or []:
        for d in pt.get("descriptions") or []:
            cwe = d.get("cweId")
            if isinstance(cwe, str) and cwe not in cwes:
                cwes.append(cwe)
    affected = []
    for a in cna.get("affected") or []:
        versions = []
        for v in a.get("versions") or []:
            spec = {k: v[k] for k in ("version", "status", "lessThan", "lessThanOrEqual")
                    if v.get(k)}
            if spec:
                versions.append(spec)
        affected.append({"vendor": a.get("vendor"), "product": a.get("product"),
                         "versions": versions[:20]})
    result = {
        "cve_id": cve_id,
        "title": scrub(cna.get("title")),
        "description": scrub(_english(cna.get("descriptions"))),
        "cwe_ids": cwes,
        "affected": affected[:10],
        "published": meta.get("datePublished"),
    }
    return scrub_advisory(result)
