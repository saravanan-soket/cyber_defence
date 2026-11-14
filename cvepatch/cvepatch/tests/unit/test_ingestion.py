"""Ingestion: identifiers, dedup, provenance, Chrome-vs-V8 (spec §15.2-4, §6)."""

from __future__ import annotations

import json

import pytest

from cvepatch.core.ingestion import identifiers as I
from cvepatch.core.ingestion.advisory_resolver import resolve_candidate_commits
from cvepatch.core.ingestion.chromium_issue_client import ChromiumIssueClient
from cvepatch.core.ingestion.cve_client import (
    CveClient,
    CveClientError,
    RetryableFetchError,
)
from cvepatch.core.ingestion.lifecycle import Status
from cvepatch.core.ingestion.patch_resolver import (
    mark_absent,
    mark_claimed,
    verify_with_content,
)
from cvepatch.core.ingestion.store import CandidateStore


# -- identifier normalization (§15.2) --------------------------------------
@pytest.mark.parametrize("raw,want", [
    ("cve 2024 1939", "CVE-2024-1939"),
    ("CVE-2024-1939", "CVE-2024-1939"),
    ("cve_2024_1939", "CVE-2024-1939"),
])
def test_normalize_cve(raw, want):
    assert I.normalize_cve(raw) == want


def test_normalize_crbug_variants():
    assert I.normalize_crbug("crbug.com/40062462") == "crbug-40062462"
    assert I.normalize_crbug("issue 40062462") == "crbug-40062462"


def test_normalize_any_disambiguates():
    assert I.normalize_any("CVE-2024-1939").kind == "cve"
    assert I.normalize_any("crbug.com/333333").kind == "crbug"
    assert I.normalize_any("deadbeefcafe").kind == "commit"


def test_affects_v8_distinguishes_chrome_from_v8():
    assert I.affects_v8("V8", "turbofan type confusion") is True
    assert I.affects_v8("Blink>DOM", "use after free in DOM") is False
    assert I.affects_v8(None, "WebAssembly Liftoff bug") is True


# -- dedup + provenance + lifecycle (§15.3-4) ------------------------------
def test_store_dedup_and_merge():
    s = CandidateStore()
    s.ingest_cve({"cve_id": "CVE-2024-1939", "description": "V8 wasm bug",
                  "source_url": "u", "affects_v8_candidate": True})
    s.ingest_source_ref(repository="https://chromium.googlesource.com/v8/v8",
                        vulnerable_commit="abcdef1234567",
                        cve_id="CVE-2024-1939", chromium_issue_id="crbug.com/40062462")
    assert len(s) == 1
    c = s.all()[0]
    assert c.identifiers["cve"] == "CVE-2024-1939"
    assert c.identifiers["crbug"] == "crbug-40062462"
    assert c.lifecycle.status == Status.CLASSIFIED
    assert c.affects_v8_candidate is True


def test_store_evidence_is_deduped():
    s = CandidateStore()
    s.ingest_cve({"cve_id": "CVE-2024-1939", "description": "x",
                  "source_url": "u", "affects_v8_candidate": True})
    before = len(s.all()[0].evidence)
    s.ingest_cve({"cve_id": "CVE-2024-1939", "description": "x",
                  "source_url": "u", "affects_v8_candidate": True})
    assert len(s.all()[0].evidence) == before  # no duplicate evidence


def test_ingest_jsonl(tmp_path):
    p = tmp_path / "m.jsonl"
    p.write_text("\n".join([
        json.dumps({"cve_id": "CVE-2024-0001", "product": "v8", "component": "V8"}),
        json.dumps({"chromium_issue_id": "crbug.com/55555", "component": "Blink"}),
    ]))
    s = CandidateStore()
    out = s.ingest_jsonl(p)
    assert len(out) == 2
    assert len(s) == 2


# -- advisory -> candidate commit is NEVER verified (§6.6, §6.10) ----------
def test_advisory_candidate_commits_are_not_verified():
    res = resolve_candidate_commits([
        "https://chromium.googlesource.com/v8/v8/+/abc1234def5678",
        "https://example.com/not-a-commit",
    ])
    assert len(res.candidate_commits) == 1
    assert res.candidate_commits[0].confidence == "candidate"
    assert res.unresolved == ("https://example.com/not-a-commit",)


def test_patch_provenance_claimed_vs_verified_vs_absent():
    cc = resolve_candidate_commits(
        ["https://github.com/x/y/commit/abc1234def5678"]).candidate_commits[0]
    claimed = mark_claimed(cc)
    assert claimed.provenance.status == "claimed"
    assert claimed.provenance.content_sha256 is None  # link alone is not proof

    verified = verify_with_content("abc1234def5678",
                                   authoritative_source="gitiles",
                                   patch_content=b"--- a\n+++ b\n")
    assert verified.provenance.status == "verified"
    assert verified.provenance.content_sha256 is not None

    absent = mark_absent()
    assert absent.provenance.status == "absent"
    assert absent.commit is None


# -- CVE client: cache, offline, retry (§6.8-9) ----------------------------
def _nvd_payload(cve="CVE-2024-1939"):
    return {"vulnerabilities": [{"cve": {
        "descriptions": [{"lang": "en", "value": "V8 type confusion in WebAssembly"}],
        "weaknesses": [{"description": [{"value": "CWE-843"}]}],
        "references": [{"url": "https://chromium.googlesource.com/v8/v8/+/deadbeef12345"}],
    }}]}


def test_cve_client_uses_cache_without_network(tmp_path):
    calls = {"n": 0}

    def fetcher(url):
        calls["n"] += 1
        return json.dumps(_nvd_payload()).encode()

    client = CveClient(cache_dir=tmp_path, fetcher=fetcher, refresh_days=30)
    rec = client.get("CVE-2024-1939")
    assert rec.cwe_ids == ("CWE-843",)
    assert rec.affects_v8_candidate is True
    # second call served from fresh cache -> no extra fetch
    client.get("CVE-2024-1939")
    assert calls["n"] == 1


def test_cve_client_retries_then_serves_stale_cache(tmp_path):
    # Seed a cache, then make the fetcher always fail transiently + force refresh.
    client = CveClient(cache_dir=tmp_path, refresh_days=0, retries=2,
                       fetcher=lambda u: (_ for _ in ()).throw(RetryableFetchError("boom")))
    client.seed_cache("CVE-2024-1939", _nvd_payload())
    # refresh_days=0 => cache considered fresh, so get() returns cache directly.
    rec = client.get("CVE-2024-1939")
    assert rec.cve_id == "CVE-2024-1939"


def test_cve_client_hard_failure_without_cache(tmp_path):
    client = CveClient(cache_dir=tmp_path, refresh_days=30, retries=1,
                       fetcher=lambda u: (_ for _ in ()).throw(CveClientError("404")))
    with pytest.raises(CveClientError):
        client.get("CVE-2099-9999")


# -- inaccessible / missing issue handled explicitly (§6.7) ----------------
def test_chromium_inaccessible_issue_is_explicit(tmp_path):
    client = ChromiumIssueClient(cache_dir=tmp_path)
    rec = client.mark_inaccessible("crbug.com/12345", note="security restricted")
    assert rec.accessible is False
    assert rec.affects_v8_candidate is False
    assert rec.evidence is None
