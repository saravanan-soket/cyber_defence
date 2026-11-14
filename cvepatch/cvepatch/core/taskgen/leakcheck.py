"""Is the upstream fix anywhere in a setup image? (runs inside that image)

A setup episode has network and root, so the agent could have fetched the
fixed project (a git clone, a newer release, a distro package of the project
itself). Two checks over the whole filesystem, minus the vulnerable tree and
our own code:

  1. lines the fix ADDS that appear nowhere in the vulnerable tree — a file
     holding at least half of them (min 2) is the fixed code;
  2. any .git directory that contains the fix commit.

  python -m cvepatch.core.taskgen.leakcheck --patch fix.patch \
      --baseline /opt/defensive/baseline --fix-commit <sha>

Prints one JSON object; exit 0 = clean, 1 = leak found, 2 = could not check.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

MIN_LEN = 24
MAX_PATTERNS = 40
MAX_READ = 32 * 1024 * 1024
# Never scanned: the vulnerable tree itself, our verifier/MCP code, kernel fs.
EXCLUDE = ("/proc", "/sys", "/dev", "/run", "/opt/defensive", "/rlenv/src", "/opt/hidden",
           "/opt/pkg", "/opt/venv", "/opt/vpy", "/rlenv/workspace")


def added_lines(patch: str) -> list[str]:
    return [ln[1:].strip() for ln in patch.splitlines()
            if ln.startswith("+") and not ln.startswith("+++")]


def patterns(patch: str, baseline: Path, limit: int = MAX_PATTERNS) -> list[str]:
    """Distinctive added lines: long, with letters, and absent from the vulnerable tree."""
    cands = sorted({a for a in added_lines(patch) if len(a) >= MIN_LEN and re.search(r"[A-Za-z]", a)},
                   key=len, reverse=True)
    keep: list[str] = []
    for c in cands:
        r = subprocess.run(["grep", "-rqIF", "--", c, str(baseline)], capture_output=True)
        if r.returncode == 1:           # 1 = not found; 0 found; 2 error (keep out)
            keep.append(c)
            if len(keep) >= limit:
                break
    return keep


def _excluded(p: str) -> bool:
    return any(p == e or p.startswith(e + "/") for e in EXCLUDE)


def scan_roots(root: str = "/") -> list[str]:
    """Top-level dirs to grep, expanding any dir that contains an excluded path."""
    out, todo = [], [root]
    while todo:
        d = todo.pop()
        try:
            kids = [os.path.join(d, k) for k in os.listdir(d)]
        except OSError:
            continue
        for k in kids:
            if _excluded(k) or os.path.islink(k):
                continue
            if any(e.startswith(k + "/") for e in EXCLUDE) and os.path.isdir(k):
                todo.append(k)
            else:
                out.append(k)
    return sorted(out)


def file_hits(pats: list[str], roots: list[str]) -> list[dict]:
    if not pats or not roots:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".pats", delete=False) as fh:
        fh.write("\n".join(pats) + "\n")
    try:
        r = subprocess.run(["grep", "-rlIF", "-f", fh.name, "--", *roots],
                           capture_output=True, text=True)
    finally:
        os.unlink(fh.name)
    hits = []
    for path in r.stdout.splitlines():
        try:
            with open(path, "rb") as f:
                text = f.read(MAX_READ).decode("utf-8", errors="replace")
        except OSError:
            continue
        n = sum(1 for p in pats if p in text)
        hits.append({"path": path, "hits": n})
    return sorted(hits, key=lambda h: -h["hits"])


def git_dirs_with(sha: str, root: str = "/") -> list[str]:
    found = []
    for d, dirs, _ in os.walk(root):
        if _excluded(d):
            dirs[:] = []
            continue
        if ".git" in dirs:
            g = os.path.join(d, ".git")
            r = subprocess.run(["git", "--git-dir", g, "cat-file", "-e", f"{sha}^{{commit}}"],
                               capture_output=True)
            if r.returncode == 0:
                found.append(g)
            dirs.remove(".git")
    return found


def check(patch: str, baseline: Path, fix_commit: str | None, root: str = "/") -> dict:
    pats = patterns(patch, baseline)
    hits = file_hits(pats, scan_roots(root))
    need = max(2, math.ceil(len(pats) / 2))
    leaked_files = [h for h in hits if h["hits"] >= need]
    gits = git_dirs_with(fix_commit, root) if fix_commit else []
    return {"patterns": len(pats), "threshold": need,
            "leak": bool(leaked_files or gits),
            "checked_lines": len(pats) >= 2,
            "leaked_files": leaked_files[:10], "partial_hits": hits[:10],
            "git_dirs_with_fix": gits}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--patch", type=Path, required=True)
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--fix-commit", default=None)
    ap.add_argument("--root", default="/")
    a = ap.parse_args(argv)
    try:
        res = check(a.patch.read_text(errors="replace"), a.baseline, a.fix_commit, a.root)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"error": f"{type(e).__name__}: {e}"}))
        return 2
    print(json.dumps(res))
    return 1 if res["leak"] else 0


if __name__ == "__main__":
    sys.exit(main())
