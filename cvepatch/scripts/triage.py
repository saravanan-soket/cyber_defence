#!/usr/bin/env python3
"""Corpus-scale triage: which CVEs could become defensive tasks?

Reads the full CVE list (CVEProject/cvelistV5 release zip) and the OSV.dev
bulk export (all.zip) WITHOUT extracting them, joins OSV records to CVE ids
via OSV `id`/`aliases`, and classifies every CVE through the defensive-task
funnel:

  1. published        — not REJECTED/RESERVED
  2. open_source      — evidence the vulnerable code is public (source-code
                        ecosystem in OSV, a repo URL, or a commit URL)
  3. fix_commit       — a concrete fixing commit is known (OSV GIT range
                        `fixed` event, or a commit URL in references)
  4. builder_track    — the ecosystem has a plausible builder (language pkg
                        ecosystems, OSS-Fuzz C/C++, generic git C/C++, kernel)
  5. oracle           — `strong` when a reproducer exists (OSS-Fuzz), else
                        `unverified` (needs a per-commit test check)

Metadata only — no builds, no code execution. Stage 5 beyond OSS-Fuzz is NOT
measured here (it needs each fix commit inspected); see --sample-commits.

Usage:
  python scripts/triage.py --cve-zip cvelist.zip.zip --osv-zip osv_all.zip \
      --out report_dir
"""

from __future__ import annotations

import argparse
import io
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from cvepatch.core.taskgen.commit_ref import from_osv, parse_commit_url

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Commit URL shapes -> (host_kind). Captures the sha.
COMMIT_URL_RES = [
    re.compile(r"github\.com/[^/]+/[^/]+/commit/([0-9a-f]{7,40})", re.I),
    re.compile(r"gitlab\.[^/]+/.+/-/commit/([0-9a-f]{7,40})", re.I),
    re.compile(r"bitbucket\.org/[^/]+/[^/]+/commits?/([0-9a-f]{7,40})", re.I),
    re.compile(r"googlesource\.com/.+/\+/([0-9a-f]{7,40})", re.I),
    re.compile(r"git\.kernel\.org/.+(?:commit|id=)/?\??(?:id=)?([0-9a-f]{12,40})", re.I),
    re.compile(r"[?&;]h=([0-9a-f]{12,40})", re.I),          # gitweb / cgit
    re.compile(r"/commit/\?id=([0-9a-f]{12,40})", re.I),    # cgit
]
REPO_URL_RE = re.compile(
    r"(github\.com|gitlab\.com|bitbucket\.org|googlesource\.com|git\.kernel\.org|sourceforge\.net/p/|savannah\.gnu\.org)",
    re.I,
)

# OSV ecosystem -> builder track.
LANG_ECOS = {
    "PyPI": "python", "npm": "javascript", "Maven": "java", "Go": "go",
    "crates.io": "rust", "Packagist": "php", "RubyGems": "ruby", "NuGet": "dotnet",
    "Hex": "elixir", "Pub": "dart", "Hackage": "haskell", "GHC": "haskell",
    "CRAN": "r", "Julia": "julia", "opam": "ocaml", "SwiftURL": "swift",
    "GitHub Actions": "github-actions", "VSCode": "vscode-ext",
}
DISTRO_ECOS = {
    "AlmaLinux", "Alpaquita", "Alpine", "Azure Linux", "BellSoft Hardened Containers",
    "Bitnami", "Chainguard", "CleanStart", "Debian", "Echo", "Mageia", "MinimOS",
    "Red Hat", "Rocky Linux", "SUSE", "TuxCare", "Ubuntu", "Wolfi", "openEuler",
    "openSUSE", "Root",
}


def ecosystem_track(eco: str) -> str | None:
    base = eco.split(":", 1)[0]
    if base in LANG_ECOS:
        return "lang:" + LANG_ECOS[base]
    if base == "OSS-Fuzz":
        return "oss-fuzz-c/c++"
    if base == "GIT":
        return "git-generic"
    if base == "Linux":
        return "linux-kernel"
    if base == "Android":
        return "android"
    if base in DISTRO_ECOS:
        return "distro-pkg"
    return None


def commit_shas(urls) -> set[str]:
    out = set()
    for u in urls:
        for rx in COMMIT_URL_RES:
            m = rx.search(u or "")
            if m:
                out.add(m.group(1).lower())
                break
    return out


def iter_zip_json(zf: zipfile.ZipFile, suffix: str = ".json"):
    for info in zf.infolist():
        if info.is_dir() or not info.filename.endswith(suffix):
            continue
        try:
            with zf.open(info) as fh:
                yield info.filename, json.load(fh)
        except Exception:  # noqa: BLE001 - malformed record: skip, count elsewhere
            yield info.filename, None


def open_cve_zip(path: Path) -> zipfile.ZipFile:
    """cvelistV5 release is a zip containing `cves.zip`; open the inner one.

    The inner zip is read fully into memory (~0.5-1 GB) because random access
    into a deflated member of the outer zip would be pathologically slow.
    """
    outer = zipfile.ZipFile(path)
    inner_names = [n for n in outer.namelist() if n.endswith(".zip")]
    if inner_names:
        data = outer.read(inner_names[0])
        return zipfile.ZipFile(io.BytesIO(data))
    return outer


def load_osv(osv_zip: Path):
    """Index OSV records by CVE id (via id + aliases)."""
    by_cve: dict[str, dict] = defaultdict(lambda: {
        "ecosystems": set(), "fix_shas": set(), "repos": set(), "osv_ids": set(),
        "fix_refs": [],
        "oss_fuzz": False,
    })
    n = bad = 0
    with zipfile.ZipFile(osv_zip) as zf:
        for _name, rec in iter_zip_json(zf):
            n += 1
            if not isinstance(rec, dict):
                bad += 1
                continue
            cves = {a for a in ([rec.get("id")] + list(rec.get("aliases") or []))
                    if isinstance(a, str) and CVE_RE.match(a)}
            if not cves:
                continue
            ecos, shas, repos, oss_fuzz, refs_ = set(), set(), set(), False, []
            for aff in rec.get("affected") or []:
                eco = ((aff.get("package") or {}).get("ecosystem")) or ""
                if eco:
                    ecos.add(eco)
                    if eco.startswith("OSS-Fuzz"):
                        oss_fuzz = True
                for rng in aff.get("ranges") or []:
                    if rng.get("type") == "GIT":
                        if rng.get("repo"):
                            repos.add(rng["repo"])
                        for ev in rng.get("events") or []:
                            if ev.get("fixed"):
                                shas.add(str(ev["fixed"]).lower())
                                ref = from_osv(rng.get("repo"), str(ev["fixed"]))
                                if ref:
                                    refs_.append(ref)
            refs = rec.get("references") or []
            shas |= commit_shas(r.get("url") for r in refs if r.get("type") in ("FIX", "WEB", "PACKAGE", None))
            for r in refs:
                if REPO_URL_RE.search(r.get("url") or ""):
                    repos.add(r["url"])
                ref = parse_commit_url(r.get("url") or "")
                if ref:
                    refs_.append(ref)
            for c in cves:
                d = by_cve[c]
                d["ecosystems"] |= ecos
                d["fix_shas"] |= shas
                d["repos"] |= repos
                d["osv_ids"].add(rec.get("id"))
                d["fix_refs"] += refs_
                d["oss_fuzz"] = d["oss_fuzz"] or oss_fuzz
    return by_cve, n, bad


def fix_refs(urls, osv_rec, limit: int = 5) -> list[dict]:
    """Clonable (repo, sha) pairs for a CVE: commit links in the CVE record first,
    then OSV GIT ranges; GitHub first within each, de-duplicated by sha."""
    cands = [r for r in (parse_commit_url(u) for u in urls) if r]
    cands += list(osv_rec["fix_refs"]) if osv_rec else []
    cands.sort(key=lambda r: "github.com/" not in r.repo.lower())   # stable
    out, seen = [], set()
    for r in cands:
        if r.sha[:7] in seen:
            continue
        seen.add(r.sha[:7])
        out.append({"repo": r.repo, "sha": r.sha, **({"alt_repos": list(r.alt_repos)} if r.alt_repos else {})})
    return out[:limit]


def is_v8(cna: dict, desc: str) -> bool:
    text = desc.lower()
    prods = " ".join(f"{a.get('vendor','')} {a.get('product','')}" for a in cna.get("affected") or []).lower()
    return (" v8 " in f" {text} ".replace(",", " ").replace(".", " ")
            or "in v8" in text or "v8 in google chrome" in text
            or ("chrome" in prods and "v8" in text))


def triage(cve_zip: Path, osv_zip: Path, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    print("[1/2] indexing OSV ...", file=sys.stderr)
    osv, osv_n, osv_bad = load_osv(osv_zip)
    print(f"      OSV records={osv_n} malformed={osv_bad} CVEs-with-OSV={len(osv)}", file=sys.stderr)

    print("[2/2] scanning CVE list ...", file=sys.stderr)
    funnel = Counter()
    tracks = Counter()
    fix_tracks = Counter()
    oracle = Counter()
    by_year = defaultdict(Counter)
    v8 = Counter()
    rows_path = out / "cve_triage.jsonl"
    cve_zf = open_cve_zip(cve_zip)
    with rows_path.open("w") as rows:
        for _name, rec in iter_zip_json(cve_zf):
            if not isinstance(rec, dict):
                funnel["malformed"] += 1
                continue
            meta = rec.get("cveMetadata") or {}
            cid = meta.get("cveId")
            if not cid or not CVE_RE.match(cid):
                continue
            funnel["0_total"] += 1
            year = cid.split("-")[1]
            by_year[year]["total"] += 1
            if meta.get("state") != "PUBLISHED":
                funnel["x_rejected_or_reserved"] += 1
                continue
            funnel["1_published"] += 1
            cna = (rec.get("containers") or {}).get("cna") or {}
            adps = (rec.get("containers") or {}).get("adp") or []
            urls = [r.get("url", "") for r in cna.get("references") or []]
            for adp in adps:
                urls += [r.get("url", "") for r in adp.get("references") or []]
            desc = next((d.get("value", "") for d in cna.get("descriptions") or []
                         if d.get("lang", "").startswith("en")), "")
            repo_fields = [a.get("repo") or a.get("collectionURL") or "" for a in cna.get("affected") or []]

            o = osv.get(cid)
            ecos = o["ecosystems"] if o else set()
            trk = {t for t in (ecosystem_track(e) for e in ecos) if t}
            src_tracks = trk - {"distro-pkg"}
            shas = commit_shas(urls) | (o["fix_shas"] if o else set())
            has_repo = bool(o and o["repos"]) or any(REPO_URL_RE.search(u or "") for u in urls + repo_fields)

            open_source = bool(src_tracks) or has_repo or bool(shas)
            # primary track (priority order)
            primary = None
            for pref in ("oss-fuzz-c/c++", "linux-kernel", "android"):
                if pref in trk:
                    primary = pref
                    break
            if primary is None:
                langs = sorted(t for t in trk if t.startswith("lang:"))
                if langs:
                    primary = langs[0]
                elif "git-generic" in trk or (open_source and shas):
                    primary = "git-generic"
                elif "distro-pkg" in trk:
                    primary = "distro-pkg"
                elif open_source:
                    primary = "repo-unmapped"
                else:
                    primary = "no-source-evidence"
            tracks[primary] += 1

            gh = next((m.group(0) for u in urls
                       for m in [re.search(r"https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", u or "", re.I)] if m), None)
            row = {"cve": cid, "year": year, "open_source": open_source, "github_commit": gh,
                   "fix_refs": fix_refs(urls, o),
                   "track": primary, "fix_commits": sorted(shas)[:5],
                   "n_fix_commits": len(shas), "oss_fuzz": bool(o and o["oss_fuzz"]),
                   "v8": False}
            if open_source:
                funnel["2_open_source"] += 1
                by_year[year]["open_source"] += 1
            if open_source and shas:
                funnel["3_fix_commit_known"] += 1
                by_year[year]["fix_commit"] += 1
                fix_tracks[primary] += 1
                buildable = primary not in ("distro-pkg", "repo-unmapped", "no-source-evidence")
                if buildable:
                    funnel["4_builder_track"] += 1
                    if row["oss_fuzz"]:
                        oracle["strong (OSS-Fuzz reproducer)"] += 1
                        funnel["5a_oracle_strong"] += 1
                    else:
                        oracle["unverified (needs test check)"] += 1
                        funnel["5b_oracle_unverified"] += 1
            if is_v8(cna, desc):
                row["v8"] = True
                v8["total"] += 1
                if shas:
                    v8["fix_commit_known"] += 1
                if any("chromium.googlesource.com/v8" in u for u in urls):
                    v8["v8_repo_commit_ref"] += 1
            rows.write(json.dumps(row) + "\n")

    report = {
        "sources": {"cve_zip": cve_zip.name, "osv_zip": osv_zip.name,
                    "osv_records": osv_n, "cves_with_osv_entry": len(osv)},
        "funnel": dict(sorted(funnel.items())),
        "primary_track_all_published": dict(tracks.most_common()),
        "primary_track_with_fix_commit": dict(fix_tracks.most_common()),
        "oracle": dict(oracle),
        "v8": dict(v8),
        "by_year": {y: dict(c) for y, c in sorted(by_year.items())},
    }
    (out / "report.json").write_text(json.dumps(report, indent=2))
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cve-zip", type=Path, required=True)
    ap.add_argument("--osv-zip", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    rep = triage(a.cve_zip, a.osv_zip, a.out)
    print(json.dumps({k: rep[k] for k in ("funnel", "oracle", "v8")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
