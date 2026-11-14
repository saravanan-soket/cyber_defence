"""The '*** Begin Patch' (V4A) format gpt-oss uses for apply_patch."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cvepatch.core.validation import v4a_patch


def _tree(tmp: Path) -> tuple[Path, callable]:
    root = (tmp / "src")
    root.mkdir()
    (root / "a.c").write_text("int f(int n) {\n    if (n > cap) n = cap;\n    return n;\n}\n")
    (root / "old.txt").write_text("bye\n")
    root = root.resolve()

    def resolve(p):
        t = (root / p).resolve()
        try:
            t.relative_to(root)
            return t
        except ValueError:
            return None
    return root, resolve


def test_add_update_delete_move(tmp_path):
    root, res = _tree(tmp_path)
    patch = """*** Begin Patch
*** Add File: scripts/install.sh
+#!/usr/bin/env bash
+apt-get install -y libfoo-dev
*** Update File: a.c
@@ int f(int n) {
-    if (n > cap) n = cap;
+    if (n >= cap) n = cap - 1;
     return n;
*** Delete File: old.txt
*** End Patch"""
    touched = v4a_patch.apply(patch, root, res)
    assert set(touched) == {"scripts/install.sh", "a.c", "old.txt"}
    assert (root / "scripts/install.sh").read_text() == "#!/usr/bin/env bash\napt-get install -y libfoo-dev\n"
    assert "n >= cap" in (root / "a.c").read_text() and (root / "a.c").read_text().endswith("}\n")
    assert not (root / "old.txt").exists()
    move = "*** Begin Patch\n*** Update File: a.c\n*** Move to: b.c\n@@\n-    return n;\n+    return n + 0;\n*** End Patch"
    v4a_patch.apply(move, root, res)
    assert not (root / "a.c").exists() and "return n + 0;" in (root / "b.c").read_text()


def test_whitespace_tolerant_context(tmp_path):
    root, res = _tree(tmp_path)
    patch = "*** Begin Patch\n*** Update File: a.c\n@@\n-  if (n > cap) n = cap;   \n+    if (n >= cap) n = cap - 1;\n*** End Patch"
    v4a_patch.apply(patch, root, res)
    assert "n >= cap" in (root / "a.c").read_text()


def test_all_or_nothing(tmp_path):
    root, res = _tree(tmp_path)
    before = (root / "a.c").read_text()
    bad = ("*** Begin Patch\n*** Update File: a.c\n@@\n-    return n;\n+    return 0;\n"
           "*** Update File: a.c\n@@\n-this line is not there\n+x\n*** End Patch")
    with pytest.raises(v4a_patch.V4AError, match="could not find"):
        v4a_patch.apply(bad, root, res)
    assert (root / "a.c").read_text() == before
    with pytest.raises(v4a_patch.V4AError, match="not writable"):
        v4a_patch.apply("*** Begin Patch\n*** Add File: ../escape.txt\n+x\n*** End Patch", root, res)
    with pytest.raises(v4a_patch.V4AError, match="no such file to update"):
        v4a_patch.apply("*** Begin Patch\n*** Update File: nope.c\n@@\n-x\n+y\n*** End Patch", root, res)


def test_toolbox_apply_patch_accepts_v4a_and_absolute_paths(tmp_path):
    from cvepatch.core.mcp_server.tools import DefensiveToolbox
    fixture = Path(__file__).resolve().parents[3] / "testenvs" / "cvepatch-fixture"
    src = tmp_path / "src"
    shutil.copytree(fixture / "baseline", src)
    box = DefensiveToolbox(source_dir=src, workspace_dir=tmp_path / "ws",
                           task_path=fixture / "public" / "defensive_task.json")
    r = box.apply_patch(f"*** Begin Patch\n*** Add File: {box.candidate_dir}/notes/n.txt\n+hello\n"
                        f"*** Add File: {src}/notes/m.txt\n+redirected\n*** End Patch")
    assert r["ok"] and r["format"] == "v4a", r
    assert (box.candidate_dir / "notes/n.txt").read_text() == "hello\n"
    assert (box.candidate_dir / "notes/m.txt").read_text() == "redirected\n"   # source path -> copy
    assert not (src / "notes").exists()
    assert not box.apply_patch("*** Begin Patch\n*** Add File: /etc/x\n+no\n*** End Patch")["ok"]
