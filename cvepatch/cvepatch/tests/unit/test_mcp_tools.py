"""MCP tool registration schema sanity (regression for the **kwargs bug).

A prior wrapper registered every tool as `lambda(**kwargs)`, so FastMCP
advertised a bogus `kwargs` object parameter and agents could not call any
tool. These tests pin the registered functions' signatures so the tool
surface the model sees stays correct, without needing FastMCP installed.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from cvepatch.core.mcp_server.tools import DefensiveToolbox, register_tools

FIX = Path("testenvs/defensive-fixture")


class _RecorderMCP:
    """Minimal stand-in for FastMCP: captures the functions register_tools wires."""

    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self, name: str):
        def deco(fn):
            self.tools[name] = fn
            return fn
        return deco


def _box(tmp_path: Path) -> DefensiveToolbox:
    return DefensiveToolbox(
        source_dir=FIX / "baseline",
        workspace_dir=tmp_path / "ws",
        task_path=FIX / "task" / "defensive_task.json",
    )


PATCH_TOOLS = {"setup", "read_file", "list_directory", "search_code", "inspect_diff",
               "apply_patch", "write_file", "run_command", "submit_fix", "submit_report"}


def test_all_expected_tools_registered(tmp_path, monkeypatch):
    monkeypatch.delenv("DEF_LEGACY_TOOLS", raising=False)
    mcp = _RecorderMCP()
    register_tools(mcp, _box(tmp_path))
    assert set(mcp.tools) == PATCH_TOOLS
    legacy = _RecorderMCP()
    monkeypatch.setenv("DEF_LEGACY_TOOLS", "1")
    register_tools(legacy, _box(tmp_path))
    assert set(legacy.tools) == PATCH_TOOLS | {"run_static_analysis", "run_tests", "submit_patch"}


def test_setup_mode_tools_and_clean_descriptions(tmp_path, monkeypatch):
    monkeypatch.delenv("DEF_LEGACY_TOOLS", raising=False)
    box = _box(tmp_path)
    box.mode = "setup"
    mcp = _RecorderMCP()
    register_tools(mcp, box)
    assert "submit_setup" in mcp.tools and "submit_fix" not in mcp.tools
    assert "network access" in mcp.tools["run_command"].__doc__
    patch = _RecorderMCP()
    register_tools(patch, _box(tmp_path))
    for name, fn in patch.tools.items():
        doc = fn.__doc__ or ""
        assert len(doc) > 40 and "\n" not in doc, name      # one clean paragraph each
    assert "no network" in patch.tools["run_command"].__doc__.lower()
    # grade_defensive must NOT be exposed on the episode surface.
    assert "grade_defensive" not in mcp.tools


def test_no_tool_uses_var_keyword(tmp_path):
    """The **kwargs bug: no registered tool may take *args/**kwargs — FastMCP
    would turn those into a single bogus object parameter."""
    mcp = _RecorderMCP()
    register_tools(mcp, _box(tmp_path))
    for name, fn in mcp.tools.items():
        for pname, p in inspect.signature(fn).parameters.items():
            assert p.kind not in (p.VAR_KEYWORD, p.VAR_POSITIONAL), (
                f"{name}() exposes variadic param {pname!r} -> bad MCP schema"
            )


def test_setup_takes_no_required_args(tmp_path):
    mcp = _RecorderMCP()
    register_tools(mcp, _box(tmp_path))
    sig = inspect.signature(mcp.tools["setup"])
    required = [p for p in sig.parameters.values()
               if p.default is inspect._empty and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)]
    assert required == []


def test_registered_tools_are_callable_and_return_json(tmp_path):
    import json
    mcp = _RecorderMCP()
    register_tools(mcp, _box(tmp_path))
    out = mcp.tools["setup"]()
    parsed = json.loads(out)
    assert parsed["task_profile"]["interface"] == "rl.mcp.vulnerability_defense.v1"
    # a required-arg tool has exactly that param
    assert list(inspect.signature(mcp.tools["read_file"]).parameters) == ["path"]


def test_candidate_workspace_is_writable_from_readonly_baseline(tmp_path):
    """Regression: the task image mounts the source baseline read-only; the
    copied candidate workspace must be made writable or apply_patch/build fail
    with EACCES (the agent then can never submit a fix)."""
    import os
    import stat
    # Make a read-only copy of the fixture baseline (mimics chmod -R a-w /rlenv/src).
    ro_src = tmp_path / "ro_src"
    import shutil
    shutil.copytree(FIX / "baseline", ro_src)
    for dp, dns, fns in os.walk(ro_src):
        for n in (*dns, *fns):
            p = os.path.join(dp, n)
            os.chmod(p, os.stat(p).st_mode & ~0o222)  # strip all write bits

    box = DefensiveToolbox(source_dir=ro_src, workspace_dir=tmp_path / "ws",
                           task_path=FIX / "task" / "defensive_task.json")
    # Candidate dir + its files must be owner-writable.
    cand = box.candidate_dir
    assert os.access(cand, os.W_OK)
    f = cand / "src" / "strbuf.c"
    assert f.stat().st_mode & stat.S_IWUSR, "candidate file not writable"
    # And apply_patch must succeed against it.
    patch = (FIX / "reference" / "fix.patch").read_text()
    res = box.apply_patch(patch)
    assert res["ok"] is True, res
