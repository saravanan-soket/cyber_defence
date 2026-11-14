#!/usr/bin/env python3
"""Host step for every language: pick CVEs from the triage rows and write
task bundles. Clones and reads diffs only; never runs repository code.

  python scripts/taskgen.py --rows <cve_triage.jsonl> \
      --lang go,python,javascript,java,rust,php,ruby --n 20 \
      --cache <git cache> --out runs/defensive-tasks

Writes <out>/<lang>/<task bundles>, <out>/<lang>/lifecycle.jsonl (one row per
CVE with status + reason) and <out>/split_summary.json.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

from cvepatch.core.taskgen.commit_ref import CommitRef, fallbacks, parse_commit_url
from cvepatch.core.taskgen.core import NoCodeFix, SkipCandidate, build_task
from cvepatch.core.taskgen.languages import ADAPTERS


def status_for(reason: str) -> str:
    """Skip reason -> lifecycle status."""
    if reason.startswith(("clone failed", "git ")) or "archive" in reason:
        return "FAILED"
    if "no oracle" in reason or "test functions" in reason or "not top-level" in reason:
        return "INCONCLUSIVE"
    return "UNSUPPORTED"


def commit_refs(row: dict) -> list[CommitRef]:
    """Fix commits to try, best first. Rows from triage.py carry `fix_refs` (any git
    host); older rows only have `github_commit`."""
    refs = [CommitRef(f["repo"], f["sha"],
                      tuple(dict.fromkeys((*fallbacks(f["repo"]), *f.get("alt_repos", ())))))
            for f in row.get("fix_refs") or []]
    if not refs and row.get("github_commit"):
        refs = [r for r in [parse_commit_url(row["github_commit"])] if r]
    return refs


def build_first(row: dict, refs: list[CommitRef], **kw) -> tuple[dict, CommitRef]:
    """build_task on the first ref that clones; other skips are final.

    With keep_all, a ref whose commit has no code change (a version bump, CI,
    docs...) is passed over for the CVE's next ref; if none has code, the first
    usable one is kept anyway (labelled ref=no_code_fix)."""
    keep_all = kw.get("keep_all", False)
    no_code: list[CommitRef] = []
    for i, ref in enumerate(refs):
        try:
            return build_task(row["cve"], ref, **{**kw, "allow_no_code": not keep_all}), ref
        except NoCodeFix:
            no_code.append(ref)
        except SkipCandidate as e:
            if i == len(refs) - 1 or not str(e).startswith(("clone failed", "git fetch")):
                if not no_code:
                    raise
                break
    if no_code:
        return build_task(row["cve"], no_code[0], **{**kw, "allow_no_code": True}), no_code[0]
    raise SkipCandidate("no fix commit")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=Path, required=True)
    ap.add_argument("--lang", default=",".join(ADAPTERS))
    ap.add_argument("--n", type=int, default=20, help="CVEs sampled per language")
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--advisories", type=Path, default=None,
                    help="advisories.jsonl from scripts/extract_advisories.py "
                         "(default: next to --rows)")
    ap.add_argument("--github-only", action="store_true",
                    help="only CVEs with a GitHub fix commit (the original pool)")
    ap.add_argument("--rebuild", action="store_true",
                    help="regenerate bundles even when a complete one exists")
    a = ap.parse_args()

    rows = [json.loads(ln) for ln in a.rows.open()]
    adv_path = a.advisories or a.rows.parent / "advisories.jsonl"
    advisories: dict[str, dict] = {}
    if adv_path.is_file():
        for ln in adv_path.open():
            d = json.loads(ln)
            advisories[d["cve_id"]] = d
    else:
        print(f"warning: no advisories at {adv_path}; agents will get no CVE text",
              file=sys.stderr)
    summary = {}
    for lang in [x.strip() for x in a.lang.split(",") if x.strip()]:
        ad = ADAPTERS[lang]
        pool = [r for r in rows if r["track"] == ad.track
                and (r.get("github_commit") if a.github_only else commit_refs(r))]
        random.Random(a.seed).shuffle(pool)
        sample = pool[: a.n]
        out = a.out / lang
        out.mkdir(parents=True, exist_ok=True)
        stats = Counter()
        with (out / "lifecycle.jsonl").open("w") as log:
            for i, r in enumerate(sample, 1):
                refs = commit_refs(r)
                rec = {"cve": r["cve"], "lang": lang, "commit": f"{refs[0].repo}@{refs[0].sha}"}
                try:
                    meta, used = build_first(r, refs, cache=a.cache, out_root=out, adapter=ad,
                                             reuse=not a.rebuild, advisory=advisories.get(r["cve"]))
                    rec["commit"] = f"{used.repo}@{used.sha}"
                    rec.update(status="CLASSIFIED", task_id=meta["task_id"], image=meta.get("image"),
                               reason=("existing bundle reused" if meta.get("reused")
                                       else "bundle written; awaiting confirmation"))
                except SkipCandidate as e:
                    rec.update(status=status_for(str(e)), reason=str(e))
                except Exception as e:  # noqa: BLE001 - record and keep going
                    rec.update(status="FAILED", reason=f"{type(e).__name__}: {e}"[:300])
                stats[rec["status"]] += 1
                log.write(json.dumps(rec) + "\n")
                log.flush()
                print(f"[{lang} {i}/{len(sample)}] {r['cve']}: {rec['status']} - {rec['reason'][:80]}",
                      file=sys.stderr, flush=True)
        summary[lang] = {"pool": len(pool), "sampled": len(sample), "by_status": dict(stats)}
    (a.out / "split_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
