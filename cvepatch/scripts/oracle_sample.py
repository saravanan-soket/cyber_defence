#!/usr/bin/env python3
"""Estimate oracle availability: do fix commits ship a test?

Samples CVE triage rows (from defensive_triage.py) that have a GitHub fix
commit, fetches `<commit>.patch` (plain web URL, no API token needed), and
checks whether the fix touches a test file. A test landing with the fix is the
best candidate for the defensive task's trusted regression oracle.

Reads metadata only (diff headers); never executes fetched content.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

DIFF_PATH_RE = re.compile(r"^diff --git a/(\S+) b/", re.M)
TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|testing|testdata|test-suite|regress)(/|$)"
    r"|(^|/)test_[^/]+\.py$|_test\.(py|go|rb|c|cc|cpp)$|\.(test|spec)\.[jt]sx?$"
    r"|(^|/)[^/]*Tests?\.(java|kt|cs|scala)$|_spec\.rb$|Test\.php$",
    re.I,
)


def fetch_patch_paths(commit_url: str, timeout: float = 20.0) -> list[str] | None:
    url = commit_url.rstrip("/") + ".patch"
    req = urllib.request.Request(url, headers={"User-Agent": "cvepatch-defensive-triage/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
            # Only the header region matters; cap the read.
            text = r.read(2_000_000).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise
        return None
    except Exception:  # noqa: BLE001
        return None
    return DIFF_PATH_RE.findall(text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=Path, required=True, help="cve_triage.jsonl")
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--sleep", type=float, default=0.7)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()

    eligible = defaultdict(list)
    skip = {"distro-pkg", "repo-unmapped", "no-source-evidence"}
    for line in a.rows.open():
        r = json.loads(line)
        if r.get("github_commit") and r.get("track") not in skip:
            eligible[r["track"]].append(r)
    total = sum(len(v) for v in eligible.values())
    rng = random.Random(a.seed)
    # Proportional stratified sample by track (at least 5 per track when available).
    sample = []
    for rows in eligible.values():
        k = max(min(5, len(rows)), round(a.n * len(rows) / total))
        sample += rng.sample(rows, min(k, len(rows)))

    stats = defaultdict(Counter)
    results = []
    for i, r in enumerate(sample):
        try:
            paths = fetch_patch_paths(r["github_commit"])
        except urllib.error.HTTPError:
            print("rate limited (429); backing off 60s", file=sys.stderr)
            time.sleep(60)
            paths = fetch_patch_paths(r["github_commit"])
        trk = r["track"]
        if paths is None:
            stats[trk]["unreachable"] += 1
            outcome = "unreachable"
        else:
            touches = any(TEST_PATH_RE.search(p) for p in paths)
            stats[trk]["with_test" if touches else "no_test"] += 1
            outcome = "with_test" if touches else "no_test"
        results.append({"cve": r["cve"], "track": trk, "commit": r["github_commit"],
                        "outcome": outcome, "files": (paths or [])[:30]})
        if (i + 1) % 25 == 0:
            print(f"  {i+1}/{len(sample)}", file=sys.stderr)
        time.sleep(a.sleep)

    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "oracle_sample.jsonl").write_text("\n".join(json.dumps(x) for x in results) + "\n")
    summary = {
        "eligible_rows_with_github_fix": total,
        "sampled": len(sample),
        "by_track": {t: dict(c) for t, c in stats.items()},
    }
    agg = Counter()
    for c in stats.values():
        agg.update(c)
    reached = agg["with_test"] + agg["no_test"]
    summary["overall"] = dict(agg)
    summary["with_test_rate_of_reachable"] = round(agg["with_test"] / reached, 3) if reached else None
    (a.out / "oracle_sample_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
