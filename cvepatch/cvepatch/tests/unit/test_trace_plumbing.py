"""Diff splitting, grader-only mounts, Langfuse episode events, trace export."""

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

from cvepatch.contract.manifest import load as load_env_manifest
from cvepatch.core.validation.patch_validator import diff_paths, split_diff
from cvepatch.runner import cli_oneshot_grader
from cvepatch.runner.langfuse_sync import build_batch, episode_events, tool_calls_of

REPO = Path(__file__).resolve().parents[3]

GIT_DIFF = """diff --git a/src/a.c b/src/a.c
--- a/src/a.c
+++ b/src/a.c
@@ -1 +1 @@
-x
+y
diff --git a/tests/t.c b/tests/t.c
new file mode 100644
--- /dev/null
+++ b/tests/t.c
@@ -0,0 +1 @@
+int main(void){return 0;}
"""
PLAIN_DIFF = """--- a/src/a.c
+++ b/src/a.c
@@ -1 +1 @@
-x
+y
--- /dev/null
+++ b/tests/t.c
@@ -0,0 +1 @@
+z
"""


@pytest.mark.parametrize("diff", [GIT_DIFF, PLAIN_DIFF])
def test_split_diff(diff):
    assert diff_paths(diff) == ["src/a.c", "tests/t.c"]
    test, rest = split_diff(diff, ["./tests/t.c"])
    assert "tests/t.c" in test and "src/a.c" not in test
    assert "src/a.c" in rest and "tests/t.c" not in rest


def test_manifest_mounts_resolve_next_to_manifest():
    m = load_env_manifest(REPO / "testenvs" / "cvepatch-fixture" / "env_manifest.yaml")
    (src, target), = m.grader_mounts
    assert target == "/opt/hidden"
    assert Path(src) == (REPO / "testenvs" / "cvepatch-fixture" / "hidden").resolve()


def test_grader_gets_hidden_mount_read_only(monkeypatch, tmp_path):
    seen = {}

    class Proc:
        returncode = 0

        async def communicate(self):
            return b'{"tier": "T4", "capabilities": {"fix_applies": true}}', b""

    async def fake_exec(*argv, **_kw):
        seen["argv"] = argv
        return Proc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    res = asyncio.run(cli_oneshot_grader.run_cli_oneshot_grader(
        image_ref="local/x:latest", command=["verify"], run_dir=tmp_path,
        mounts=[(str(hidden), "/opt/hidden")]))
    argv = list(seen["argv"])
    assert f"{hidden.resolve()}:/opt/hidden:ro" in argv
    assert argv.index("--network") < argv.index("local/x:latest")
    assert res.capabilities == {"fix_applies": True}
    with pytest.raises(cli_oneshot_grader.GraderError):
        asyncio.run(cli_oneshot_grader.run_cli_oneshot_grader(
            image_ref="local/x:latest", command=["v"], run_dir=tmp_path,
            mounts=[(str(tmp_path / "missing"), "/opt/hidden")]))


TRANSCRIPT = [
    {"ts": "t0", "role": "human", "content": "Call setup()."},
    {"ts": "t1", "role": "ai", "content": "", "served_model": "glm-5.3",
     "reasoning_content": "First I should read the advisory.",
     "tool_calls": "[{'id': 'c1', 'name': 'setup', 'args': {}}]",
     "usage": {"input_tokens": 10, "output_tokens": 5, "reasoning_tokens": 3}},
    {"ts": "t2", "role": "tool", "tool_call_id": "c1", "name": "setup", "content": "{}"},
    {"ts": "t3", "role": "ai", "content": "done", "served_model": "glm-5.3"},
]


def test_episode_events_named_spans_and_thinking():
    ev = episode_events("tr1", TRANSCRIPT, tools=["setup", "run_command"])
    kinds = [(e["type"], e["body"].get("name")) for e in ev]
    # tools-offered first, then agent-thinking per turn and a span per tool call
    assert kinds[0] == ("span-create", "tools-offered")
    assert ("generation-create", "agent-thinking") in kinds
    assert ("span-create", "setup") in kinds        # tool span named by the tool
    gen = next(e for e in ev if e["body"].get("name") == "agent-thinking")
    assert gen["body"]["output"] == "First I should read the advisory."   # thinking shown directly
    assert gen["body"]["metadata"]["tool_calls"] == ["setup"]
    assert gen["body"]["metadata"]["has_reasoning"] is True
    assert gen["body"]["usageDetails"] == {"input": 10, "output": 5, "reasoning": 3}
    setup_span = next(e for e in ev if e["body"].get("name") == "setup")
    assert setup_span["body"]["input"] == {} and setup_span["body"]["output"] == "{}"


def test_build_batch_trace_spans_and_scores():
    verdict = {"tier": "T2", "cve_id": "CVE-2099-1", "final_status": "PATCH_VERIFIED",
               "checks": {"fix_applies": True, "upstream_test_passes_on_fix": None,
                          "agent_test_fails_on_vuln": True}}
    ev = build_batch("tr1", verdict, TRANSCRIPT, run_id="r1", env_id="defensive-go-x",
                     model="openai/glm-5.3", lang="go", tools=["setup"])
    assert ev[0]["type"] == "trace-create"
    trace = ev[0]["body"]
    assert trace["id"] == "tr1" and trace["sessionId"] == "patchcve-CVE-2099-1"
    assert trace["name"] == "cvepatch:CVE-2099-1"
    assert {"tier:T2", "cve:CVE-2099-1", "lang:go"} <= set(trace["tags"])
    names = [e["body"].get("name") for e in ev]
    assert "tools-offered" in names and "agent-thinking" in names
    scores = {e["body"]["name"]: e["body"] for e in ev if e["type"] == "score-create"}
    assert scores["tier"]["value"] == "T2" and scores["tier_rank"]["value"] == 3
    assert scores["fix_applies"]["value"] == 1 and scores["fix_applies"]["dataType"] == "BOOLEAN"
    assert "upstream_test_passes_on_fix" not in scores   # None = not evaluated


def test_tool_calls_of_handles_list_and_repr():
    assert tool_calls_of([{"id": "a"}]) == [{"id": "a"}]
    assert tool_calls_of("[{'id': 'a', 'args': {}}]") == [{"id": "a", "args": {}}]
    assert tool_calls_of("not python") == []


def _export_module():
    spec = importlib.util.spec_from_file_location("export_traces",
                                                  REPO / "scripts" / "export_traces.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_export_filters_by_tier_and_keeps_reasoning(tmp_path):
    ex = _export_module()
    for name, tier in (("good", "T1"), ("bad", "rejected")):
        d = tmp_path / "runs" / name
        d.mkdir(parents=True)
        (d / "transcript.jsonl").write_text("".join(json.dumps(e) + "\n" for e in TRANSCRIPT))
        (d / "grade_calls.jsonl").write_text(json.dumps(
            {"source": "cli_oneshot", "result": {"tier": tier, "cve_id": "CVE-2099-1"}}) + "\n")
        (d / "tools.json").write_text(json.dumps(
            [{"name": "setup", "description": "d", "input_schema": {"type": "object"}}]))
    out = tmp_path / "t.jsonl"
    import sys
    argv = sys.argv
    sys.argv = ["x", "--runs", str(tmp_path / "runs"), "--out", str(out), "--min-tier", "T2"]
    try:
        ex.main()
    finally:
        sys.argv = argv
    rows = [json.loads(ln) for ln in out.read_text().splitlines()]
    assert [r["id"] for r in rows] == ["good"]
    msgs = rows[0]["messages"]
    assert msgs[1]["reasoning_content"] == "First I should read the advisory."
    assert msgs[1]["tool_calls"][0]["function"] == {"name": "setup", "arguments": "{}"}
    assert msgs[2] == {"role": "tool", "tool_call_id": "c1", "name": "setup", "content": "{}"}
    assert rows[0]["tools"][0]["function"]["name"] == "setup"


def test_trace_labels_become_tags_and_metadata():
    from cvepatch.runner.langfuse_sync import build_batch
    ev = build_batch("tr", {"tier": "T4", "cve_id": "CVE-2099-1"}, [], run_id="r", env_id="e",
                     model="m", labels={"env": "unbuilt", "deps_changed": True, "confirm": None})
    trace = ev[0]["body"]
    assert "env:unbuilt" in trace["tags"] and "deps_changed:True" in trace["tags"]
    assert not any(t.startswith("confirm:") for t in trace["tags"])
    assert trace["metadata"]["labels"]["env"] == "unbuilt"


def test_tools_offered_carries_descriptions_and_parameters(tmp_path):
    from cvepatch.runner.langfuse_sync import build_batch, read_tools
    (tmp_path / "tools.json").write_text(json.dumps([
        {"name": "run_command", "description": "Run a shell command (bash).",
         "input_schema": {"type": "object", "properties": {"command": {"type": "string"}},
                          "required": ["command"]}}]))
    tools = read_tools(tmp_path)
    fn = tools[0]["function"]
    assert fn["name"] == "run_command" and fn["description"].startswith("Run a shell")
    assert fn["parameters"]["required"] == ["command"]
    ev = build_batch("tr", {"tier": "T4"}, [], run_id="r", env_id="e", model="m", tools=tools)
    span = next(e["body"] for e in ev if e["body"].get("name") == "tools-offered")
    assert span["output"][0]["function"]["description"] and span["metadata"]["tool_names"] == ["run_command"]
