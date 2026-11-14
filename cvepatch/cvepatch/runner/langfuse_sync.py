"""Build one readable Langfuse trace per episode, from the local transcript.

The LiteLLM proxy's own callback logs each call as a flat `litellm-acompletion`
generation with no structure — unreadable for an agent loop. So, like the
attacking traces, we build the trace ourselves after the episode, as a tree of
named observations keyed by the run's trace id and grouped into a per-CVE
session:

  trace          name cvepatch:<CVE>, session = CVE/env id, input = init prompt
  tools-offered  span: the tool surface the agent was given (once, at the top)
  agent-thinking generation per model turn: output = {reasoning, content,
                 tool_calls}, input = the messages so far, token usage
  <tool>         span per tool call, named by the tool (setup/exec/run_command/
                 submit_fix/...): input = args, output = result
  score          tier (categorical), tier_rank (numeric), one per boolean check

The proxy's own trace metadata is deliberately NOT set (see litellm_client),
so its flat generations don't land on this trace. The full transcript with
reasoning stays in the run dir for scripts/export_traces.py.

Best-effort: missing keys or HTTP errors only log. Uses the public ingestion
API (POST {LANGFUSE_HOST}/api/public/ingestion, basic auth public:secret).
"""

from __future__ import annotations

import ast
import json
import logging
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

TIER_RANK = {"T1": 4, "T2": 3, "T3": 2, "T4": 1, "rejected": 0}
TOOL_OUTPUT_CHARS = 20_000
BATCH_SIZE = 40


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _ev(kind: str, body: dict[str, Any], ts: str | None = None) -> dict[str, Any]:
    return {"id": str(uuid.uuid4()), "timestamp": ts or _now(), "type": kind, "body": body}


def tool_calls_of(raw: Any) -> list[dict[str, Any]]:
    """Transcript tool_calls are a list, or (older runs) its repr string."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            val = ast.literal_eval(raw)
            return val if isinstance(val, list) else []
        except (ValueError, SyntaxError):
            return []
    return []


def read_transcript(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "transcript.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _clip(s: str) -> str:
    return s[:TOOL_OUTPUT_CHARS] + ("\n<truncated>" if len(s) > TOOL_OUTPUT_CHARS else "")


def read_tools(run_dir: Path) -> list[dict[str, Any]]:
    """The tool definitions the model was given (name, description, parameters),
    in the OpenAI function format it saw them in."""
    path = run_dir / "tools.json"
    if not path.is_file():
        return []
    try:
        return [{"type": "function", "function": {
                    "name": t["name"], "description": t.get("description") or "",
                    "parameters": t.get("input_schema") or {"type": "object", "properties": {}}}}
                for t in json.loads(path.read_text()) if t.get("name")]
    except (json.JSONDecodeError, OSError, TypeError, KeyError):
        return []


def tool_name(t: Any) -> str | None:
    return t if isinstance(t, str) else ((t.get("function") or {}).get("name") or t.get("name"))


def episode_events(trace_id: str, entries: list[dict[str, Any]],
                   tools: list[Any] | None = None) -> list[dict[str, Any]]:
    """tools-offered + agent-thinking generations + per-tool spans (pure)."""
    events: list[dict[str, Any]] = []
    first_ts = next((e.get("ts") for e in entries), _now())
    if tools:
        events.append(_ev("span-create", {
            "id": str(uuid.uuid4()), "traceId": trace_id, "name": "tools-offered",
            "startTime": first_ts, "endTime": first_ts, "output": tools,
            "metadata": {"tool_names": [tool_name(t) for t in tools]}}, first_ts))
    pending: list[dict[str, Any]] = []      # user/tool messages since the last turn
    args_by_call: dict[str, Any] = {}
    last_ts: str | None = None
    turn = 0
    for e in entries:
        role, ts = e.get("role"), e.get("ts")
        if role == "ai":
            turn += 1
            calls = tool_calls_of(e.get("tool_calls"))
            for c in calls:
                if isinstance(c, dict) and c.get("id"):
                    args_by_call[c["id"]] = c.get("args")
            usage = e.get("usage") or {}
            reasoning = (e.get("reasoning_content") or "").strip()
            content = (e.get("content") or "").strip()
            call_names = [c.get("name") for c in calls if isinstance(c, dict)]
            # Name the node for what it actually holds, and show that text as the
            # output (a string, so Langfuse renders it directly) — so an
            # "agent-thinking" node always contains the model's thinking, and a
            # mechanical tool-only turn reads as "agent-step", not empty thinking.
            if reasoning:
                name, out = "agent-thinking", reasoning
            elif content and not calls:
                name, out = "agent-response", content
            else:
                name = "agent-step"
                out = content or ("calling " + ", ".join(call_names) if call_names else "(no output)")
            events.append(_ev("generation-create", {
                "id": str(uuid.uuid4()), "traceId": trace_id, "name": name,
                "startTime": last_ts or ts, "endTime": ts, "model": e.get("served_model"),
                "input": pending, "output": out,
                "metadata": {"content": content, "tool_calls": call_names,
                             "has_reasoning": bool(reasoning)},
                "usageDetails": {k: v for k, v in {
                    "input": usage.get("input_tokens"), "output": usage.get("output_tokens"),
                    "reasoning": usage.get("reasoning_tokens")}.items() if v is not None},
            }, ts))
            pending = []
        elif role == "tool":
            content = _clip(str(e.get("content") or ""))
            events.append(_ev("span-create", {
                "id": str(uuid.uuid4()), "traceId": trace_id, "name": e.get("name") or "tool",
                "startTime": last_ts or ts, "endTime": ts,
                "input": args_by_call.get(e.get("tool_call_id")), "output": content}, ts))
            pending.append({"role": "tool", "name": e.get("name"), "content": content})
        elif role == "human":
            pending.append({"role": "user", "content": e.get("content")})
        last_ts = ts or last_ts
    return events


def build_batch(trace_id: str, verdict: dict[str, Any], entries: list[dict[str, Any]], *,
                run_id: str, env_id: str, model: str, lang: str | None = None,
                tools: list[Any] | None = None, phase: str = "patch",
                labels: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """All ingestion events for one episode's readable trace (pure; tested)."""
    tier = verdict.get("tier") or "rejected"
    cve = verdict.get("cve_id")
    tags = [f"tier:{tier}", f"env:{env_id}"] + ([f"cve:{cve}"] if cve else []) \
        + ([f"lang:{lang}"] if lang else []) + [f"phase:{phase}"] \
        + [f"{k}:{v}" for k, v in sorted((labels or {}).items())
           if isinstance(v, (str, int, float, bool)) and v != ""]
    prefix = "cvepatch" if phase == "patch" else f"cvepatch-{phase}"
    first = next((e.get("content") for e in entries if e.get("role") == "human"), None)
    events = [_ev("trace-create", {
        "id": trace_id, "name": f"{prefix}:{cve or env_id}",
        # One session per CVE: its setup trace and every patch attempt.
        "sessionId": f"patchcve-{cve or env_id}",
        "tags": tags, "input": first,
        "output": {"tier": tier, "final_status": verdict.get("final_status"),
                   "submission": verdict.get("submission")},
        "metadata": {"run_id": run_id, "env_id": env_id, "model": model, "cve_id": cve,
                     "lang": lang, "tier": tier, "phase": phase, "labels": labels or {},
                     "checks": verdict.get("checks"),
                     "verifier_version": verdict.get("verifier_version"),
                     "failure_reasons": verdict.get("failure_reasons")},
    })]
    events += episode_events(trace_id, entries, tools)

    def score(name: str, value: Any, data_type: str) -> None:
        events.append(_ev("score-create", {"id": str(uuid.uuid4()), "traceId": trace_id,
                                           "name": name, "value": value, "dataType": data_type}))

    score("tier", tier, "CATEGORICAL")
    score("tier_rank", TIER_RANK.get(tier, 0), "NUMERIC")
    for name, val in (verdict.get("checks") or {}).items():
        if isinstance(val, bool):
            score(name, 1 if val else 0, "BOOLEAN")
    return events


def post_episode(trace_id: str | None, verdict: dict[str, Any], run_dir: Path, *,
                 run_id: str, env_id: str, model: str, lang: str | None = None,
                 timeout_s: float = 30.0, phase: str = "patch",
                 labels: dict[str, Any] | None = None) -> bool:
    """Post one episode as a trace. Labels (dataset filters: confirm status,
    env quality, deps_changed, ...) come from `labels` and from the
    CVEPATCH_TRACE_LABELS env var (JSON) set by scripts/worker.py."""
    host = os.environ.get("LANGFUSE_HOST")
    pk = os.environ.get("LANGFUSE_PUBLIC_KEY")
    sk = os.environ.get("LANGFUSE_SECRET_KEY")
    if not (host and pk and sk):
        log.info("[%s] langfuse sync skipped: LANGFUSE_* not set", run_id)
        return False
    trace_id = trace_id or f"{env_id}-{run_id[:12]}"
    run_dir = Path(run_dir)
    try:
        env_labels = json.loads(os.environ.get("CVEPATCH_TRACE_LABELS") or "{}")
    except ValueError:
        env_labels = {}
    events = build_batch(trace_id, verdict, read_transcript(run_dir), run_id=run_id,
                         env_id=env_id, model=model, lang=lang, tools=read_tools(run_dir),
                         phase=phase, labels={**env_labels, **(labels or {})})
    ok = True
    for i in range(0, len(events), BATCH_SIZE):
        try:
            r = httpx.post(f"{host.rstrip('/')}/api/public/ingestion",
                           json={"batch": events[i:i + BATCH_SIZE]}, auth=(pk, sk),
                           timeout=timeout_s)
        except httpx.HTTPError as exc:
            log.warning("[%s] langfuse sync failed: %s", run_id, exc)
            return False
        if r.status_code not in (200, 201, 207):
            log.warning("[%s] langfuse sync HTTP %s: %s", run_id, r.status_code, r.text[:200])
            return False
        try:
            errors = r.json().get("errors")
        except ValueError:
            errors = None
        if errors:
            ok = False
            log.warning("[%s] langfuse sync partial errors: %s", run_id, str(errors)[:300])
    log.info("[%s] langfuse trace synced: trace=%s events=%d tier=%s", run_id, trace_id,
             len(events), verdict.get("tier"))
    try:   # run dirs written by the pods are root-owned when re-posted from the host
        (run_dir / "langfuse.json").write_text(
            json.dumps({"trace_id": trace_id, "events": len(events), "ok": ok}))
    except OSError:
        log.info("[%s] could not write langfuse.json in %s", run_id, run_dir)
    return ok
