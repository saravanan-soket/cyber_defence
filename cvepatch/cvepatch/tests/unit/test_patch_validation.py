"""Patch parsing, path-traversal rejection, application (spec §15.5-6, §9)."""

from __future__ import annotations

import pytest

from cvepatch.core.validation.patch_validator import (
    PatchValidationError,
    apply_patch_to_tree,
    validate_patch,
)

GOOD = """--- a/src/strbuf.c
+++ b/src/strbuf.c
@@ -1,2 +1,2 @@
-old
+new
"""


def test_valid_diff_parses():
    info = validate_patch(GOOD)
    assert "src/strbuf.c" in info.paths
    assert info.num_hunks == 1
    assert len(info.sha256) == 64


def test_empty_patch_rejected_when_required():
    with pytest.raises(PatchValidationError):
        validate_patch("", require_nonempty=True)


def test_empty_patch_allowed_when_not_required():
    info = validate_patch("", require_nonempty=False)
    assert info.paths == ()


@pytest.mark.parametrize("bad", [
    "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n",
    "--- a//etc/shadow\n+++ b//etc/shadow\n@@ -1 +1 @@\n-x\n+y\n",
    "--- /etc/hosts\n+++ /etc/hosts\n@@ -1 +1 @@\n-x\n+y\n",
])
def test_path_traversal_and_absolute_rejected(bad):
    with pytest.raises(PatchValidationError):
        validate_patch(bad)


def test_allowlist_flags_out_of_tree_edits():
    patch = """--- a/tests/regression_test.c
+++ b/tests/regression_test.c
@@ -1 +1 @@
-x
+y
"""
    info = validate_patch(patch, allowlist=("src/strbuf.c",))
    assert info.disallowed == ("tests/regression_test.c",)


def test_no_hunks_rejected():
    with pytest.raises(PatchValidationError):
        validate_patch("--- a/x\n+++ b/x\n")


def test_apply_to_tree_and_symlink_escape(tmp_path):
    # Build a tiny tree with a file to patch.
    (tmp_path / "src").mkdir()
    f = tmp_path / "src" / "a.txt"
    f.write_text("old\n")
    patch = "--- a/src/a.txt\n+++ b/src/a.txt\n@@ -1 +1 @@\n-old\n+new\n"
    info = validate_patch(patch)
    res = apply_patch_to_tree(info, tmp_path)
    assert res.ok, res.detail
    assert f.read_text() == "new\n"


def test_apply_rejects_symlink_escape(tmp_path):
    # A symlinked directory component that points outside the checkout.
    outside = tmp_path / "outside"
    outside.mkdir()
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / "src").symlink_to(outside)  # src -> outside the checkout
    patch = "--- a/src/evil.txt\n+++ b/src/evil.txt\n@@ -1 +1 @@\n-x\n+y\n"
    info = validate_patch(patch)
    res = apply_patch_to_tree(info, checkout)
    assert res.ok is False
    assert "escape" in res.detail.lower()
