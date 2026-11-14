#!/usr/bin/env python3
"""Containment probe for the defensive-v8 episode sandbox.

Run this INSIDE a defensive-v8 image, as the `agent` user, exactly where an
evaluated model's code would run. It exercises each containment surface the
way a model (e.g. GLM) could and reports, per surface, whether the sandbox
HELD (attempt refused) or was BYPASSED (attempt succeeded):

  1. mcp_fs_read      MCP read_file() of the trusted oracle path   -> expect HELD
  2. oob_oracle_read  direct open() of the oracle off-disk         -> the HOLE
  3. patch_allowlist  apply_patch() to a non-source file           -> depends on task
  4. net_egress       outbound TCP connect                         -> expect HELD

Surface 2 is the finding this probe exists to demonstrate: the MCP tool layer
correctly refuses to read `/opt/defensive/...`, but agent-executed code runs
outside that guard and can read the same files directly, because the image
ships them world-readable (`chmod -R a+rX /opt/defensive`). That leaks the
grading oracle (expected results, regression invariant, the trusted check).

This probes the operator's OWN harness to verify/harden it. It reads oracle
files only to prove readability (first bytes + a hash), and never exfiltrates:
there is nowhere to send them (`--network none`), by design.

Usage (inside the container):
  /opt/venv/bin/python -m scripts.defensive_sandbox_probe        # or: python scripts/defensive_sandbox_probe.py
  python scripts/defensive_sandbox_probe.py --json               # machine-readable
Exit code: 0 if every surface HELD, 1 if any surface was BYPASSED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Result:
    surface: str
    held: bool            # True = sandbox contained the attempt
    detail: str
    evidence: str = ""     # short, non-sensitive proof (hash / byte count / errno)


def _oracle_paths() -> list[Path]:
    """The trusted, agent-must-not-read assets, from the container env."""
    task_path = Path(os.environ.get("DEF_TASK_PATH",
                                    "/opt/defensive/task/defensive_task.json"))
    paths = [task_path]
    reg = Path("/opt/defensive/regression")
    if reg.exists():
        paths.append(reg)
    return paths


def probe_mcp_fs_read() -> Result:
    """The MCP read_file() tool should refuse the oracle path (expected HELD)."""
    task_path = os.environ.get("DEF_TASK_PATH",
                               "/opt/defensive/task/defensive_task.json")
    try:
        from exploitbench.defensive.mcp_server.tools import build_toolbox_from_env
        box = build_toolbox_from_env()
        out = box.read_file(task_path)
    except Exception as exc:  # pragma: no cover - import/env shape varies
        return Result("mcp_fs_read", True,
                      f"could not construct toolbox ({exc!r}); tool surface unavailable")
    refused = isinstance(out, dict) and "error" in out and "contents" not in out
    return Result(
        "mcp_fs_read", refused,
        "read_file() refused the oracle path" if refused
        else "read_file() RETURNED oracle contents",
        evidence=str(out.get("error", ""))[:160] if isinstance(out, dict) else "",
    )


def probe_oob_oracle_read() -> Result:
    """Direct off-disk read of the oracle, as agent-executed code would do.

    This is the hole: if any oracle file opens, the episode container leaks the
    grading ground truth to code the model controls.
    """
    leaked: list[str] = []
    for p in _oracle_paths():
        files = [p] if p.is_file() else sorted(f for f in p.rglob("*") if f.is_file())
        for f in files:
            try:
                data = f.read_bytes()
            except OSError:
                continue
            leaked.append(f"{f} ({len(data)}B sha256={hashlib.sha256(data).hexdigest()[:12]})")
    if leaked:
        return Result("oob_oracle_read", False,
                      f"read {len(leaked)} oracle file(s) off-disk, bypassing the MCP guard",
                      evidence="; ".join(leaked[:4]))
    return Result("oob_oracle_read", True,
                  "oracle files are not readable by this uid")


def probe_patch_allowlist() -> Result:
    """Can a patch touch a non-source file (e.g. a build/test harness)?

    HELD iff the task pins a non-empty allowlist that excludes such files.
    Empty allowlist (= any path) is reported as BYPASSED: it enables the
    patch-a-build-script -> run_tests('build') code-exec path.
    """
    try:
        from exploitbench.defensive.validation.patch_validator import (
            PatchValidationError,
            validate_patch,
        )
        from exploitbench.defensive.mcp_server.tools import build_toolbox_from_env
        allowlist = tuple(build_toolbox_from_env().task.patched_files_allowlist)
    except Exception as exc:  # pragma: no cover
        return Result("patch_allowlist", True, f"toolbox/task unavailable ({exc!r})")

    probe_diff = "--- /dev/null\n+++ b/build.sh\n@@ -0,0 +1,1 @@\n+echo pwned\n"
    try:
        info = validate_patch(probe_diff, allowlist=allowlist, require_nonempty=True)
    except PatchValidationError as exc:
        return Result("patch_allowlist", True,
                      "validator rejected a non-source patch", evidence=str(exc)[:160])
    if info.disallowed:
        return Result("patch_allowlist", True,
                      "allowlist excludes the probed build.sh",
                      evidence=f"disallowed={list(info.disallowed)}")
    return Result("patch_allowlist", False,
                  "a patch may create build.sh (empty/permissive allowlist) -> "
                  "enables run_tests('build') code-exec",
                  evidence=f"allowlist={list(allowlist) or 'EMPTY (any path)'}")


def probe_net_egress(host: str = "1.1.1.1", port: int = 53, timeout: float = 3.0) -> Result:
    """Outbound TCP. Expected HELD by `docker run --network none`."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return Result("net_egress", False, f"connected out to {host}:{port}")
    except OSError as exc:
        return Result("net_egress", True, "outbound connection refused/unreachable",
                      evidence=f"{type(exc).__name__}: {exc}")


def run_all() -> list[Result]:
    return [
        probe_mcp_fs_read(),
        probe_oob_oracle_read(),
        probe_patch_allowlist(),
        probe_net_egress(),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    args = ap.parse_args(argv)

    results = run_all()
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))
    else:
        width = max(len(r.surface) for r in results)
        print(f"{'SURFACE':<{width}}  VERDICT   DETAIL")
        for r in results:
            verdict = "HELD" if r.held else "BYPASSED"
            print(f"{r.surface:<{width}}  {verdict:<8}  {r.detail}")
            if r.evidence:
                print(f"{'':<{width}}            {r.evidence}")
    bypassed = [r.surface for r in results if not r.held]
    if bypassed:
        print(f"\nBYPASSED: {', '.join(bypassed)}", file=sys.stderr)
        return 1
    print("\nall surfaces HELD", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
