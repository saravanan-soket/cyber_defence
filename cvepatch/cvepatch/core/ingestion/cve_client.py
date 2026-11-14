"""CVE / NVD metadata client — offline-first, cached, retry-aware.

Design goals from the task spec:
  * use official public metadata (CVE.org / NVD) where possible;
  * cache with an explicit refresh policy;
  * support retryable network errors + rate limits;
  * NEVER treat a CVE description alone as proof of reproducibility.

Network access is injected as a `fetcher` callable so the standard unit-test
suite runs fully offline against the on-disk cache / fixtures. The default
fetcher uses the stdlib (no new dependency) with bounded retries + backoff.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvepatch.core.ingestion.identifiers import affects_v8, normalize_cve
from cvepatch.core.ingestion.provenance import EvidenceRef

# A fetcher takes a URL and returns raw bytes, or raises on a hard failure.
Fetcher = Callable[[str], bytes]

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/{cve}"


class CveClientError(RuntimeError):
    pass


class RetryableFetchError(CveClientError):
    """A transient fetch error (timeout / 429 / 5xx) worth retrying."""


@dataclass
class CveRecord:
    cve_id: str
    description: str | None
    cwe_ids: tuple[str, ...]
    references: tuple[str, ...]
    affects_v8_candidate: bool
    source_url: str
    evidence: EvidenceRef
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "cwe_ids": list(self.cwe_ids),
            "references": list(self.references),
            "affects_v8_candidate": self.affects_v8_candidate,
            "source_url": self.source_url,
            "evidence": self.evidence.to_dict(),
        }


def _default_fetcher(url: str, *, timeout_s: float = 20.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "cvepatch-defensive/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (429, 500, 502, 503, 504):
            raise RetryableFetchError(f"HTTP {exc.code} for {url}") from exc
        raise CveClientError(f"HTTP {exc.code} for {url}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RetryableFetchError(f"network error for {url}: {exc}") from exc


def _fetch_with_retries(
    fetcher: Fetcher, url: str, *, retries: int = 3, backoff_s: float = 1.0,
    sleep: Callable[[float], None] = time.sleep,
) -> bytes:
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return fetcher(url)
        except RetryableFetchError as exc:
            last = exc
            if attempt < retries:
                sleep(backoff_s * (2**attempt))
        except CveClientError:
            raise
    raise RetryableFetchError(f"exhausted {retries} retries for {url}: {last}")


def _parse_nvd(cve_id: str, data: dict[str, Any], source_url: str, raw_bytes: bytes) -> CveRecord:
    vulns = data.get("vulnerabilities") or []
    desc: str | None = None
    cwes: list[str] = []
    refs: list[str] = []
    component_text = ""
    if vulns:
        cve = vulns[0].get("cve", {})
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                component_text = desc or ""
                break
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)
        for r in cve.get("references", []):
            if r.get("url"):
                refs.append(r["url"])
    return CveRecord(
        cve_id=cve_id,
        description=desc,
        cwe_ids=tuple(dict.fromkeys(cwes)),
        references=tuple(dict.fromkeys(refs)),
        affects_v8_candidate=affects_v8(component_text, desc),
        source_url=source_url,
        evidence=EvidenceRef.for_content(kind="nvd", source=source_url, content=raw_bytes),
        raw=data,
    )


@dataclass
class CveClient:
    """Fetches + caches CVE records. Offline-first against `cache_dir`."""

    cache_dir: Path
    fetcher: Fetcher = _default_fetcher
    refresh_days: float = 30.0
    retries: int = 3
    _sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_path(self, cve_id: str) -> Path:
        return self.cache_dir / f"{cve_id}.nvd.json"

    def _cache_fresh(self, path: Path) -> bool:
        if not path.exists():
            return False
        if self.refresh_days <= 0:
            return True
        age_days = (time.time() - path.stat().st_mtime) / 86400.0
        return age_days <= self.refresh_days

    def get(self, cve_like: str, *, force_refresh: bool = False) -> CveRecord:
        """Return a CveRecord for `cve_like`, using cache unless stale.

        Raises CveClientError on an unrecoverable fetch/parse failure. A
        cached copy is used on a transient network failure when available.
        """
        cve_id = normalize_cve(cve_like)
        cache = self._cache_path(cve_id)
        url = NVD_CVE_API.format(cve=cve_id)

        if not force_refresh and self._cache_fresh(cache):
            raw_bytes = cache.read_bytes()
            return _parse_nvd(cve_id, json.loads(raw_bytes), f"file://{cache}", raw_bytes)

        try:
            raw_bytes = _fetch_with_retries(
                self.fetcher, url, retries=self.retries, sleep=self._sleep
            )
        except CveClientError:
            if cache.exists():
                # Serve stale cache rather than fail hard on a transient error.
                raw_bytes = cache.read_bytes()
                rec = _parse_nvd(cve_id, json.loads(raw_bytes), f"file://{cache}", raw_bytes)
                return rec
            raise

        try:
            data = json.loads(raw_bytes)
        except json.JSONDecodeError as exc:
            raise CveClientError(f"NVD returned non-JSON for {cve_id}: {exc}") from exc
        cache.write_bytes(raw_bytes)
        # Touch mtime for freshness bookkeeping.
        cache.touch()
        rec = _parse_nvd(cve_id, data, url, raw_bytes)
        rec.evidence.to_dict()  # ensure evidence constructed
        return rec

    def seed_cache(self, cve_like: str, payload: dict[str, Any]) -> Path:
        """Write a payload into the cache (used by tests / air-gapped import)."""
        cve_id = normalize_cve(cve_like)
        path = self._cache_path(cve_id)
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path
