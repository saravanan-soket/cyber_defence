"""Trusted cli_oneshot grader entrypoint for defensive tasks.

Runs in a FRESH container after the episode (the agent never sees it):

    docker run --rm --network none -v <run_dir>:/run:ro <image> \
        python -m cvepatch.core.verifier.deterministic_grader \
          --run /run --task /opt/defensive/task/defensive_task.json \
          --baseline /opt/defensive/baseline

Contract (shared `runner/cli_oneshot_grader.py`): emit a single JSON object
on stdout with a `capabilities` map and exit 0. We emit the full
validation_result (which includes `capabilities` + `final_status`), so the
runner records the defensive bitmap, and `score_for_interface` can read
`final_status` to normalize a verified cell.

The trusted baseline source + task manifest are baked into the image under a
root-owned path; the only thing read from the writable/agent side is the
submitted patch on the read-only `/run` mount. No LLM, no network.

Also usable directly on the host (tests) by passing explicit paths.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cvepatch.core import manifest as task_manifest
from cvepatch.core.report import evaluate_report
from cvepatch.core.validation import pipeline as P


def _patch_from_submit_call(entry_args: Any, entry_result: Any) -> tuple[str, str | None] | None:
    """Pull (patch_text, base_revision) from a submit_patch tool-call record.

    The patch text may be in the call's `args.patch`, or echoed in the tool's
    JSON `result` (the MCP server mirrors the submitted diff into its result
    precisely so it survives into the host-side transcript the grader reads).
    """
    # 1) args.patch (inline submission)
    if isinstance(entry_args, dict) and isinstance(entry_args.get("patch"), str) \
            and entry_args["patch"].strip():
        return entry_args["patch"], entry_args.get("base_revision")
    # 2) result JSON echo
    if isinstance(entry_result, str):
        try:
            res = json.loads(entry_result)
        except (json.JSONDecodeError, TypeError):
            res = None
        if isinstance(res, dict) and isinstance(res.get("patch"), str) and res["patch"].strip():
            return res["patch"], res.get("base_revision")
    return None


def _find_patch_text(run_dir: Path) -> tuple[str, str | None]:
    """Locate the agent's submitted patch under the read-only run mount.

    Primary source is the transcript (`tool_calls.jsonl`): the LAST
    `submit_patch` tool call wins. This is how the patch crosses from the
    agent's (now-gone) container to the fresh grader container — it rides the
    host-written transcript, not a shared filesystem. Falls back to a
    `patch_submission.json` / `candidate.patch` file if one was staged.
    Returns an empty patch when nothing was submitted (step A then fails,
    which is the correct 'no patch' outcome).
    """
    tool_log = run_dir / "tool_calls.jsonl"
    found: tuple[str, str | None] | None = None
    if tool_log.is_file():
        for line in tool_log.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("tool") != "submit_patch":
                continue
            got = _patch_from_submit_call(entry.get("args"), entry.get("result"))
            if got is not None:
                found = got  # keep the last one
    if found is not None:
        return found

    submission = run_dir / "patch_submission.json"
    if submission.is_file():
        try:
            data = json.loads(submission.read_text(encoding="utf-8"))
            return str(data.get("patch", "")), data.get("base_revision")
        except (json.JSONDecodeError, OSError):
            pass
    bare = run_dir / "candidate.patch"
    if bare.is_file():
        return bare.read_text(encoding="utf-8", errors="replace"), None
    return "", None


def _find_report(run_dir: Path) -> dict[str, Any] | None:
    """Recover the agent's root-cause report (last submit_report call wins)."""
    tool_log = run_dir / "tool_calls.jsonl"
    found: dict[str, Any] | None = None
    if tool_log.is_file():
        for line in tool_log.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("tool") != "submit_report":
                continue
            args = entry.get("args")
            if isinstance(args, dict) and isinstance(args.get("report"), dict):
                found = args["report"]
            else:
                res = entry.get("result")
                if isinstance(res, str):
                    try:
                        parsed = json.loads(res)
                        if isinstance(parsed, dict) and isinstance(parsed.get("report"), dict):
                            found = parsed["report"]
                    except json.JSONDecodeError:
                        pass
    if found is not None:
        return found
    rep = run_dir / "report.json"
    if rep.is_file():
        try:
            return json.loads(rep.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None
    return None


def grade(
    *,
    run_dir: Path,
    task_path: Path,
    baseline_dir: Path,
    work_root: Path | None = None,
) -> dict[str, Any]:
    """Run the trusted pipeline and return the validation_result dict."""
    task = task_manifest.load(task_path)
    patch_text, base_rev = _find_patch_text(run_dir)

    report_eval = None
    report_dict = _find_report(run_dir)
    if report_dict is not None:
        ev = evaluate_report(report_dict, baseline_dir)
        report_eval = ev.to_dict()

    result = P.validate(
        task,
        baseline_dir,
        patch_text,
        work_root=work_root,
        base_revision=base_rev,
        report=report_eval,
    )
    return result.to_dict()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Trusted defensive patch grader")
    ap.add_argument("--run", default="/run", help="read-only run dir mount")
    ap.add_argument("--task", default="/opt/defensive/task/defensive_task.json")
    ap.add_argument("--baseline", default="/opt/defensive/baseline")
    ap.add_argument("--work-root", default=None,
                    help="scratch dir for checkouts (default: a temp dir)")
    args = ap.parse_args(argv)

    try:
        out = grade(
            run_dir=Path(args.run),
            task_path=Path(args.task),
            baseline_dir=Path(args.baseline),
            work_root=Path(args.work_root) if args.work_root else None,
        )
    except Exception as exc:  # noqa: BLE001
        # Emit a well-formed, scorable result even on grader failure so the
        # runner records infrastructure_failure rather than a parse error.
        out = {
            "schema_version": "1",
            "task_id": "unknown",
            "grader_version": P.GRADER_VERSION,
            "final_status": "FAILED",
            "dimensions": dict.fromkeys(P._DIMENSIONS, None) | {"infrastructure_failure": True},
            "capabilities": {"infrastructure_failure": True},
            "steps": [],
            "failure_reasons": [f"grader crashed: {type(exc).__name__}: {exc}"],
            "patch_base_revision": None,
            "patch_sha256": None,
            "evidence": [],
            "report": None,
        }
    sys.stdout.write(json.dumps(out))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
