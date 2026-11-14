#!/usr/bin/env python3
"""Post episodes whose live Langfuse sync failed (e.g. Langfuse unreachable from
the pods during a cluster outage), from the local transcripts and grades.

  patch episodes: <runs>/<benchmark>/<host>/<time>/<run_id>/ with grade_calls.jsonl
  setup episodes: <tasks>/<lang>/<task>/setup_run/ with ../setup_result.json

An episode counts as synced when its langfuse.json says ok; posting writes it,
so a rerun skips what is done. Labels come from the worker's per-task results.

  set -a; . ./.env.cvepatch; set +a
  python scripts/backfill_langfuse.py --runs runs/scale/runs --tasks runs/defensive-tasks \\
      --results runs/scale/results-c100-patch --dry-run
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from cvepatch.runner.langfuse_sync import post_episode  # noqa: E402


def load(p: Path) -> dict:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return {}


LEDGER = REPO.parent / "langfuse_backfill_ledger.txt"   # run dirs posted by this script
_done: set[str] = set()


def synced(run_dir: Path) -> bool:
    return bool(load(run_dir / "langfuse.json").get("ok")) or str(run_dir.resolve()) in _done


def mark(run_dir: Path) -> None:
    _done.add(str(run_dir.resolve()))
    with LEDGER.open("a") as fh:     # run dirs are root-owned; keep our own record
        fh.write(str(run_dir.resolve()) + "\n")


def labels_for(task_id: str, results: list[Path]) -> dict:
    for r in results:
        rec = load(r / f"{task_id}.json")
        if rec.get("labels"):
            return rec["labels"]
    return {}


def patch_episodes(runs: Path):
    for g in sorted(runs.glob("*/*/*/*/grade_calls.jsonl")):
        d = g.parent
        lines = g.read_text().strip().splitlines()
        if not lines or synced(d):
            continue
        last = json.loads(lines[-1])
        verdict = last.get("result") if isinstance(last.get("result"), dict) else last
        job = load(d / "job.json")
        if not verdict or not job.get("env_id"):
            continue
        yield d, verdict, job


def setup_episodes(tasks: Path):
    for d in sorted(tasks.glob("*/*/setup_run")):
        if synced(d) or not (d / "transcript.jsonl").is_file():
            continue
        res = load(d.parent / "setup_result.json")
        if not res.get("status"):
            continue
        yield d, res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, default=REPO / "runs" / "scale" / "runs")
    ap.add_argument("--tasks", type=Path, default=REPO / "runs" / "defensive-tasks")
    ap.add_argument("--results", type=Path, action="append", default=[],
                    help="worker results dirs to take labels from (repeatable)")
    ap.add_argument("--only", choices=("patch", "setup", "both"), default="both")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if LEDGER.is_file():
        _done.update(ln.strip() for ln in LEDGER.read_text().splitlines() if ln.strip())
    stats = Counter()

    if a.only in ("patch", "both"):
        for d, verdict, job in patch_episodes(a.runs):
            task_id = job["env_id"].removeprefix("defensive-")
            cve = verdict.get("cve_id") or "CVE-" + task_id.split("-cve-", 1)[-1].upper()
            verdict = {**verdict, "cve_id": cve}
            stats["patch_pending"] += 1
            if a.dry_run:
                continue
            ok = post_episode(None, verdict, d, run_id=job["run_id"], env_id=job["env_id"],
                              model=job.get("model", "?"), lang=task_id.split("-", 1)[0],
                              phase="patch", labels=labels_for(task_id, a.results))
            stats["patch_posted" if ok else "patch_failed"] += 1
            if ok:
                mark(d)

    if a.only in ("setup", "both"):
        for d, res in setup_episodes(a.tasks):
            task_id = d.parent.name
            stats["setup_pending"] += 1
            if a.dry_run:
                continue
            verdict = {"tier": res["status"].lower(), "cve_id": res.get("cve"),
                       "checks": {"setup_submitted": res["status"] == "SETUP_OK",
                                  "recipe": bool(res.get("recipe"))},
                       "failure_reasons": [res["reason"]] if res.get("reason") else []}
            ok = post_episode(None, verdict, d, run_id=f"setup-{task_id}",
                              env_id=f"defensive-{task_id}", model=res.get("model", "?"),
                              lang=task_id.split("-", 1)[0], phase="setup",
                              labels={"setup_model": res.get("model")})
            stats["setup_posted" if ok else "setup_failed"] += 1
            if ok:
                mark(d)

    print(json.dumps(dict(stats), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
