#!/usr/bin/env python3
"""Verified episodes -> training JSONL (OpenAI chat format, reasoning kept).

  python scripts/export_traces.py --runs runs/cvepatch --out traces.jsonl --min-tier T2

Reads each run dir's transcript.jsonl (turns + reasoning), tools.json (the
tool surface the model saw) and grade_calls.jsonl (the verifier verdict).
Local files are the source of truth; Langfuse holds the same traces for
browsing. One line per episode:

  {"id", "cve_id", "env_id", "tier", "checks", "submission", "model",
   "tools": [openai function schemas],
   "messages": [{"role": "user"|"assistant"|"tool", ...}]}

Assistant messages carry `reasoning_content` alongside `content` and
`tool_calls`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cvepatch.runner.langfuse_sync import TIER_RANK, read_transcript, tool_calls_of  # noqa: E402


def verdict_of(run_dir: Path) -> dict | None:
    path = run_dir / "grade_calls.jsonl"
    if not path.is_file():
        return None
    last = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        res = d.get("result") if isinstance(d, dict) else None
        if isinstance(res, dict) and "tier" in res:
            last = res
    return last


def to_messages(entries: list[dict]) -> list[dict]:
    msgs: list[dict] = []
    for e in entries:
        role = e.get("role")
        if role == "human":
            msgs.append({"role": "user", "content": e.get("content") or ""})
        elif role == "ai":
            m: dict = {"role": "assistant", "content": e.get("content") or ""}
            if e.get("reasoning_content"):
                m["reasoning_content"] = e["reasoning_content"]
            calls = [c for c in tool_calls_of(e.get("tool_calls")) if isinstance(c, dict)]
            if calls:
                m["tool_calls"] = [{"id": c.get("id"), "type": "function",
                                    "function": {"name": c.get("name"),
                                                 "arguments": json.dumps(c.get("args") or {})}}
                                   for c in calls]
            msgs.append(m)
        elif role == "tool":
            msgs.append({"role": "tool", "tool_call_id": e.get("tool_call_id"),
                         "name": e.get("name"), "content": str(e.get("content") or "")})
    return msgs


def to_tools(run_dir: Path) -> list[dict]:
    path = run_dir / "tools.json"
    if not path.is_file():
        return []
    return [{"type": "function", "function": {"name": t["name"], "description": t.get("description"),
                                              "parameters": t.get("input_schema") or {}}}
            for t in json.loads(path.read_text())]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, required=True, help="root to search for run dirs")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--min-tier", default="T4", choices=[t for t in TIER_RANK if t != "rejected"]
                    + ["rejected"], help="keep episodes at this tier or better")
    a = ap.parse_args()
    floor = TIER_RANK[a.min_tier]
    stats: Counter = Counter()
    with a.out.open("w", encoding="utf-8") as out:
        for tr in sorted(a.runs.rglob("transcript.jsonl")):
            run_dir = tr.parent
            v = verdict_of(run_dir)
            if v is None:
                stats["no_verdict"] += 1
                continue
            tier = v.get("tier") or "rejected"
            stats[tier] += 1
            if TIER_RANK.get(tier, 0) < floor:
                continue
            entries = read_transcript(run_dir)
            job = {}
            if (run_dir / "job.json").is_file():
                job = json.loads((run_dir / "job.json").read_text())
            out.write(json.dumps({
                "id": run_dir.name, "cve_id": v.get("cve_id"), "env_id": job.get("env_id"),
                "model": job.get("model"), "tier": tier, "checks": v.get("checks"),
                "submission": v.get("submission"), "tools": to_tools(run_dir),
                "messages": to_messages(entries),
            }) + "\n")
            stats["exported"] += 1
    print(json.dumps(dict(stats), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
