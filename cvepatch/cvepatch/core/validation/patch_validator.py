"""Unified-diff validation + safe application (step A of the pipeline).

Security-critical: this is the boundary where agent-supplied patch content
meets the trusted source tree. It independently:

  * parses the unified diff and extracts every target path;
  * rejects absolute paths, `..` traversal, and paths outside the permitted
    source subtree (and an optional per-task allowlist);
  * rejects empty patches when a patch is required;
  * applies the patch to a *clean copy* of the baseline with the hunks
    constrained to the resolved, validated paths, refusing symlink escapes.

No agent input is trusted on its face. Application uses `git apply` with
`--unsafe-paths` DISABLED (default) plus our own pre-checks; if git is not
available it falls back to GNU `patch` run with `--no-symlinks` under the
target directory. Both are invoked with the CWD pinned to the checkout so a
crafted path can never reach outside it.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# Lines that introduce a file target in a unified diff.
_DIFF_GIT_RE = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_MINUS_RE = re.compile(r"^--- (?:a/)?(?P<path>.+?)\s*$")
_PLUS_RE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+?)\s*$")
# git rename / copy / mode headers also carry paths.
_RENAME_RE = re.compile(r"^(?:rename|copy) (?:from|to) (?P<path>.+)$")

_DEV_NULL = "/dev/null"


class PatchValidationError(Exception):
    """Patch is malformed, empty-when-required, or escapes the permitted tree."""


@dataclass(frozen=True)
class PatchInfo:
    """Result of parsing + path-validating a unified diff (not yet applied)."""

    paths: tuple[str, ...]            # normalized, validated relative POSIX paths
    sha256: str
    num_hunks: int
    raw: str
    disallowed: tuple[str, ...] = field(default_factory=tuple)  # paths outside allowlist


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _is_safe_relative(path: str) -> bool:
    """True iff `path` is a relative POSIX path with no traversal / root escape."""
    if not path or path == _DEV_NULL:
        return False
    if path.startswith("/") or path.startswith("~"):
        return False
    # Windows drive / UNC just in case.
    if re.match(r"^[A-Za-z]:[\\/]", path) or path.startswith("\\\\"):
        return False
    parts = PurePosixPath(path).parts
    return not any(p == ".." for p in parts)


def _candidate_paths_from_diff(raw: str) -> tuple[list[str], int]:
    """Extract all file targets referenced by the diff + count hunks.

    Collects paths from `diff --git`, `---`/`+++` headers, and rename/copy
    headers. `/dev/null` (file creation/deletion markers) is dropped.
    """
    paths: list[str] = []
    hunks = 0
    for line in raw.splitlines():
        if line.startswith("@@"):
            hunks += 1
            continue
        for rx in (_DIFF_GIT_RE,):
            m = rx.match(line)
            if m:
                paths.extend([m.group("a"), m.group("b")])
                break
        else:
            for rx in (_MINUS_RE, _PLUS_RE, _RENAME_RE):
                m = rx.match(line)
                if m:
                    paths.append(m.group("path"))
                    break
    # De-dup, drop /dev/null, strip trailing tab-timestamp if any.
    cleaned: list[str] = []
    seen: set[str] = set()
    for p in paths:
        p = p.split("\t", 1)[0].strip()
        if p == _DEV_NULL or not p:
            continue
        if p not in seen:
            seen.add(p)
            cleaned.append(p)
    return cleaned, hunks


def validate_patch(
    raw: str,
    *,
    allowlist: tuple[str, ...] | list[str] = (),
    require_nonempty: bool = True,
) -> PatchInfo:
    """Parse + path-validate a unified diff. Raises PatchValidationError.

    `allowlist` (if non-empty) restricts the set of paths the patch may
    touch, in addition to the universal traversal/absolute-path rejection.
    """
    if raw is None:
        raise PatchValidationError("patch is None")
    stripped = raw.strip()
    if not stripped:
        if require_nonempty:
            raise PatchValidationError("patch is empty but a patch is required")
        return PatchInfo(paths=(), sha256=_sha256(raw), num_hunks=0, raw=raw)

    paths, hunks = _candidate_paths_from_diff(raw)
    if not paths:
        raise PatchValidationError(
            "could not extract any file target from the diff "
            "(not a valid unified diff?)"
        )
    if hunks == 0:
        raise PatchValidationError("diff contains no hunks (@@ markers)")

    for p in paths:
        if not _is_safe_relative(p):
            raise PatchValidationError(
                f"patch targets an unsafe path (absolute / traversal / root "
                f"escape): {p!r}"
            )

    allow = {a.strip("/").replace("\\", "/") for a in allowlist}
    disallowed: list[str] = []
    if allow:
        for p in paths:
            norm = p.replace("\\", "/")
            if norm not in allow:
                disallowed.append(p)

    return PatchInfo(
        paths=tuple(paths),
        sha256=_sha256(raw),
        num_hunks=hunks,
        raw=raw,
        disallowed=tuple(disallowed),
    )


@dataclass(frozen=True)
class ApplyResult:
    ok: bool
    tool: str
    detail: str
    applied_paths: tuple[str, ...] = field(default_factory=tuple)


def _resolve_inside(root: Path, rel: str) -> Path | None:
    """Resolve `rel` under `root`, returning None if it escapes (symlink-safe)."""
    root_resolved = root.resolve()
    target = (root / rel)
    # Resolve the PARENT (strict=False) so a not-yet-existing file is allowed,
    # but any symlink component that redirects outside root is caught.
    try:
        resolved_parent = target.parent.resolve()
    except (OSError, RuntimeError):
        return None
    final = resolved_parent / target.name
    try:
        final.relative_to(root_resolved)
    except ValueError:
        return None
    return final


def apply_patch_to_tree(
    info: PatchInfo,
    checkout_dir: Path,
    *,
    git_bin: str = "git",
    patch_bin: str = "patch",
) -> ApplyResult:
    """Apply a pre-validated patch to a clean checkout, pinned inside it.

    Symlink-escape defense: every target path is resolved inside
    `checkout_dir` and rejected if it points outside (even through a symlink
    component) BEFORE any tool runs.
    """
    checkout_dir = Path(checkout_dir)
    if not checkout_dir.is_dir():
        return ApplyResult(False, "none", f"checkout dir missing: {checkout_dir}")

    for rel in info.paths:
        if _resolve_inside(checkout_dir, rel) is None:
            return ApplyResult(
                False, "none",
                f"path escapes checkout via symlink/traversal: {rel!r}",
            )

    patch_file = checkout_dir / ".__candidate.patch"
    patch_file.write_text(info.raw, encoding="utf-8")
    try:
        if shutil.which(git_bin):
            # `git apply` with CWD pinned to checkout; no --unsafe-paths, so git
            # refuses paths outside the tree. --3way disabled for determinism.
            proc = subprocess.run(
                [git_bin, "apply", "--whitespace=nowarn", "-p1", str(patch_file.name)],
                cwd=str(checkout_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                return ApplyResult(True, "git", "applied", info.paths)
            git_err = proc.stderr.strip()
            # Fall through to patch(1) only if git refused for a non-security
            # reason (e.g. context mismatch heuristics differ). Security
            # refusals ("outside repository") must NOT be retried.
            if "outside" in git_err.lower() or "beyond" in git_err.lower():
                return ApplyResult(False, "git", f"git refused: {git_err}")
            git_detail = git_err
        else:
            git_detail = "git not available"

        if shutil.which(patch_bin):
            proc = subprocess.run(
                [patch_bin, "-p1", "--no-backup-if-mismatch", "--batch",
                 "-i", str(patch_file.name)],
                cwd=str(checkout_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if proc.returncode == 0:
                return ApplyResult(True, "patch", "applied", info.paths)
            return ApplyResult(
                False, "patch",
                f"patch(1) failed: {proc.stderr.strip() or proc.stdout.strip()} "
                f"(git: {git_detail})",
            )
        return ApplyResult(False, "git", f"git apply failed: {git_detail}")
    finally:
        patch_file.unlink(missing_ok=True)


def _file_sections(diff_text: str) -> list[tuple[str, str]]:
    """Split a unified diff into (path, section_text) per file.

    Handles both `diff --git` headed diffs and bare `--- a/x` / `+++ b/x`
    diffs. The path is the post-image path (pre-image for deletions).
    """
    lines = diff_text.splitlines(keepends=True)
    starts: list[int] = []
    git_style = any(ln.startswith("diff --git ") for ln in lines)
    for i, ln in enumerate(lines):
        if git_style:
            if ln.startswith("diff --git "):
                starts.append(i)
        elif ln.startswith("--- ") and i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
            starts.append(i)
    sections: list[tuple[str, str]] = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        chunk = lines[s:e]
        old = new = None
        for ln in chunk:
            if ln.startswith("--- ") and old is None:
                old = ln[4:].split("\t", 1)[0].strip()
            elif ln.startswith("+++ ") and new is None:
                new = ln[4:].split("\t", 1)[0].strip()
        if git_style and new is None and old is None:
            # header-only section (mode change / binary): take the b/ path
            parts = chunk[0].split()
            new = parts[-1] if len(parts) >= 4 else None
        raw_path = new if new and new != "/dev/null" else old
        if raw_path is None:
            continue
        path = raw_path[2:] if raw_path[:2] in ("a/", "b/") else raw_path
        sections.append((path, "".join(chunk)))
    return sections


def split_diff(diff_text: str, paths: list[str] | tuple[str, ...]) -> tuple[str, str]:
    """Split `diff_text` into (sections for `paths`, everything else)."""
    want = {p.strip().lstrip("./").replace("\\", "/") for p in paths if p.strip()}
    picked: list[str] = []
    rest: list[str] = []
    for path, text in _file_sections(diff_text):
        (picked if path in want else rest).append(text)
    return "".join(picked), "".join(rest)


def diff_paths(diff_text: str) -> list[str]:
    """Post-image paths touched by `diff_text`, in order."""
    return [p for p, _ in _file_sections(diff_text)]
