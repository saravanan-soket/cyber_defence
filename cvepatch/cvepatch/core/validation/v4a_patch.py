"""The "V4A" patch format (OpenAI Codex apply_patch), as gpt-oss writes it.

    *** Begin Patch
    *** Add File: path/new.sh
    +line
    *** Update File: path/old.c
    *** Move to: path/renamed.c          (optional)
    @@ optional context line to find first
     context
    -removed
    +added
    *** Delete File: path/gone.txt
    *** End Patch

gpt-oss was trained on this format and uses it for any tool named
apply_patch; rejecting it made every one of its edits fail. Changes are
computed for all files first and written only if every hunk applies.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path


class V4AError(ValueError):
    pass


def is_v4a(text: str) -> bool:
    return text.lstrip().startswith("*** Begin Patch")


@dataclass
class FileOp:
    kind: str                     # add | update | delete
    path: str
    move_to: str | None = None
    lines: list[str] = field(default_factory=list)   # raw body lines


def parse(text: str) -> list[FileOp]:
    lines = text.strip("\n").splitlines()
    if not lines or lines[0].strip() != "*** Begin Patch":
        raise V4AError("missing '*** Begin Patch'")
    ops: list[FileOp] = []
    cur: FileOp | None = None
    for ln in lines[1:]:
        s = ln.rstrip("\r")
        if s.strip() == "*** End Patch":
            break
        for kind, tag in (("add", "*** Add File:"), ("update", "*** Update File:"),
                          ("delete", "*** Delete File:")):
            if s.startswith(tag):
                cur = FileOp(kind, s[len(tag):].strip())
                ops.append(cur)
                break
        else:
            if cur is None:
                raise V4AError(f"line outside a file section: {s[:80]!r}")
            if s.startswith("*** Move to:"):
                cur.move_to = s[len("*** Move to:"):].strip()
            elif s.strip() == "*** End of File":
                continue
            else:
                cur.lines.append(s)
    if not ops:
        raise V4AError("no file sections")
    for op in ops:
        if not op.path:
            raise V4AError(f"{op.kind} section without a path")
    return ops


def _hunks(body: list[str]) -> list[tuple[str | None, list[str], list[str]]]:
    """[(header, old_lines, new_lines)] from an Update File body."""
    out, header, old, new = [], None, [], []

    def flush():
        if old or new:
            out.append((header, old[:], new[:]))
    for ln in body:
        if ln.startswith("@@"):
            flush()
            header, old, new = (ln[2:].strip() or None), [], []
        elif ln.startswith("-"):
            old.append(ln[1:])
        elif ln.startswith("+"):
            new.append(ln[1:])
        else:                                  # context (' ' prefix, or a bare empty line)
            t = ln[1:] if ln.startswith(" ") else ln
            old.append(t)
            new.append(t)
    flush()
    return out


def _find(hay: list[str], needle: list[str], start: int) -> int:
    """Index of `needle` in `hay` at/after `start`: exact, then ignoring trailing
    and finally all surrounding whitespace (models often get indentation wrong)."""
    if not needle:
        return start
    for norm in (lambda x: x, str.rstrip, str.strip):
        n = [norm(x) for x in needle]
        for i in range(start, len(hay) - len(needle) + 1):
            if [norm(x) for x in hay[i:i + len(needle)]] == n:
                return i
    return -1


def apply_update(original: str, body: list[str], path: str) -> str:
    src = original.split("\n")
    trailing_nl = original.endswith("\n")
    if trailing_nl:
        src = src[:-1]
    out: list[str] = []
    cur = 0
    for header, old, new in _hunks(body):
        if header:
            h = _find(src, [header], cur)
            if h >= 0:
                out += src[cur:h]
                cur = h
        at = _find(src, old, cur)
        if at < 0:
            preview = "\n".join(old[:6])
            raise V4AError(f"{path}: could not find these lines to change:\n{preview}")
        out += src[cur:at] + new
        cur = at + len(old)
    out += src[cur:]
    return "\n".join(out) + ("\n" if trailing_nl or not original else "")


def apply(text: str, root: Path, resolve: Callable[[str], Path | None]) -> list[str]:
    """Apply a V4A patch under `root`. `resolve(path)` returns the writable target
    or None if the path is not allowed. Returns the touched paths (relative)."""
    plan: list[tuple[str, Path, str | None]] = []      # (action, target, content)
    for op in parse(text):
        target = resolve(op.path)
        if target is None:
            raise V4AError(f"path not writable: {op.path!r}")
        if op.kind == "add":
            if any(not ln.startswith("+") and ln.strip() for ln in op.lines):
                raise V4AError(f"{op.path}: every line of an added file must start with '+'")
            body = [ln[1:] if ln.startswith("+") else "" for ln in op.lines]
            plan.append(("write", target, "\n".join(body) + "\n"))
        elif op.kind == "delete":
            if not target.is_file():
                raise V4AError(f"{op.path}: no such file to delete")
            plan.append(("delete", target, None))
        else:
            if not target.is_file():
                raise V4AError(f"{op.path}: no such file to update (use *** Add File)")
            new_text = apply_update(target.read_text(encoding="utf-8", errors="replace"),
                                    op.lines, op.path)
            if op.move_to:
                dest = resolve(op.move_to)
                if dest is None:
                    raise V4AError(f"path not writable: {op.move_to!r}")
                plan += [("write", dest, new_text), ("delete", target, None)]
            else:
                plan.append(("write", target, new_text))
    touched = []
    for action, target, content in plan:
        if action == "write":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        else:
            target.unlink()
        touched.append(str(target.relative_to(root)))
    return touched
