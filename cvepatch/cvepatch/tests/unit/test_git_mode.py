"""checkout_mode=git: in-place checkout with git reset (for large trees like V8).

Runs the real pipeline on a git repo made from the fixture baseline. Requires
git and a C compiler.
"""

from __future__ import annotations

import difflib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from cvepatch.core import manifest as M
from cvepatch.core.mcp_server.tools import DefensiveToolbox
from cvepatch.core.validation import pipeline as P

pytestmark = pytest.mark.skipif(
    not (shutil.which("git") and (shutil.which("cc") or shutil.which("gcc"))),
    reason="needs git and a C compiler",
)

FIX = Path("testenvs/defensive-fixture")
REF_PATCH = (FIX / "reference" / "fix.patch").read_text()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True, capture_output=True, text=True,
    ).stdout


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    shutil.copytree(FIX / "baseline", repo, ignore=shutil.ignore_patterns("build"))
    (repo / ".gitignore").write_text("build/\n")   # build outputs are ignored, like V8's out/
    _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "vulnerable baseline")
    return repo


def _task(tmp_path: Path, **meta) -> M.DefensiveTask:
    raw = json.loads((FIX / "task" / "defensive_task.json").read_text())
    raw["metadata"] = {**raw.get("metadata", {}), "checkout_mode": "git", **meta}
    p = tmp_path / "task.json"
    p.write_text(json.dumps(raw))
    return M.load(p)


def test_git_mode_verifies_reference_fix_and_resets(tmp_path):
    repo = _repo(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")
    before = (repo / "src" / "strbuf.c").read_text()

    res = P.validate(_task(tmp_path), repo, REF_PATCH, work_root=tmp_path / "w").to_dict()

    assert res["final_status"] == "PATCH_VERIFIED", res["failure_reasons"]
    # Tree restored: same commit, vulnerable source back, no stray files.
    assert _git(repo, "rev-parse", "HEAD") == head
    assert (repo / "src" / "strbuf.c").read_text() == before
    assert P.git_tree_is_clean(repo)
    # No copies were made under work_root.
    assert not (tmp_path / "w" / "baseline").exists()
    assert not (tmp_path / "w" / "candidate").exists()
    # Ignored build outputs are kept for the next incremental build.
    assert (repo / "build" / "regression_test").exists()


def test_git_mode_rejects_suppression_patch_and_resets(tmp_path):
    repo = _repo(tmp_path)
    src = (repo / "src" / "strbuf.c").read_text()
    body = src.index("    size_t n = strlen(src);")
    neutered = src[:body] + "    dst[0] = '\\0';\n    return 0;\n}\n"
    diff = "".join(difflib.unified_diff(src.splitlines(True), neutered.splitlines(True),
                                        fromfile="a/src/strbuf.c", tofile="b/src/strbuf.c"))

    res = P.validate(_task(tmp_path), repo, diff, work_root=tmp_path / "w").to_dict()

    assert res["final_status"] != "PATCH_VERIFIED"
    assert res["dimensions"]["existing_tests_passed"] is False
    assert (repo / "src" / "strbuf.c").read_text() == src
    assert P.git_tree_is_clean(repo)


def test_git_mode_dirty_tree_is_infrastructure_failure(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "strbuf.c").write_text("/* local edit */\n")

    res = P.validate(_task(tmp_path), repo, REF_PATCH, work_root=tmp_path / "w").to_dict()

    assert res["final_status"] == "FAILED"
    assert res["dimensions"]["infrastructure_failure"] is True


def test_invalid_checkout_mode_rejected(tmp_path):
    raw = json.loads((FIX / "task" / "defensive_task.json").read_text())
    raw["metadata"] = {"checkout_mode": "rsync"}
    with pytest.raises(M.DefensiveManifestConsistencyError):
        M.from_dict(raw)


def test_toolbox_git_mode_patches_in_place_and_derives_diff(tmp_path):
    repo = _repo(tmp_path)
    task = _task(tmp_path)
    task_path = tmp_path / "task.json"
    box = DefensiveToolbox(source_dir=repo, workspace_dir=tmp_path / "ws", task_path=task_path,
                           allowed_test_commands={"build": ["bash", "build.sh"],
                                                  "regression": ["./build/regression_test"]})
    assert task.checkout_mode == "git"
    assert box.candidate_dir == repo.resolve()          # no copy
    assert not (tmp_path / "ws" / "src").exists()

    assert box.apply_patch(REF_PATCH)["ok"] is True
    tests = box.run_tests("all")["results"]
    assert tests["regression"]["exitcode"] == 0

    diff = box.inspect_diff()
    assert diff["has_changes"] and "n = cap - 1" in diff["diff"]

    # The derived diff (what submit_patch sends when no explicit patch is given)
    # must itself verify on a fresh, clean tree.
    sub = box.submit_patch()
    assert sub["ok"] is True
    fresh = _repo(tmp_path / "fresh")
    res = P.validate(task, fresh, sub["patch"], work_root=tmp_path / "w2").to_dict()
    assert res["final_status"] == "PATCH_VERIFIED", res["failure_reasons"]
