"""Agent-driven setup: adapters, submit_setup, the leak check and the driver's
bookkeeping. No Docker, no network, no LLM."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from cvepatch.core.mcp_server.tools import DefensiveToolbox
from cvepatch.core.taskgen import core, leakcheck
from cvepatch.core.taskgen.languages import ADAPTERS
from cvepatch.core.taskgen.setup_adapters import SETUP_ORACLE

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
import agent_setup  # noqa: E402

FIX_PATCH = """--- a/src/buf.c
+++ b/src/buf.c
@@ -1,3 +1,4 @@
 int copy(char *d, const char *s, unsigned n) {
-    if (n > cap) n = cap;
+    if (n >= capacity_of_destination) n = capacity_of_destination - 1;
+    d[n] = '\\0'; /* always terminate the destination buffer */
 }
"""


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    return root


@pytest.mark.parametrize("path,test", [
    ("tests/buf.c", True), ("src/test_buf.c", True), ("src/buf_test.cc", True),
    ("src/BufTest.cs", True), ("t/basic.t", True), ("fuzz/fuzz_buf.c", True),
    ("src/latest.c", False), ("lib/contest.c", False), ("src/buf.c", False),
])
def test_native_test_classification(path, test):
    assert ADAPTERS["native"].is_test(path) is test


def test_setup_plans_have_no_commands_yet(tmp_path):
    a = ADAPTERS["native"]
    p = a.plan(tmp_path, ["tests/x.c"], ["src/x.c"], "", [])
    assert p.oracle == SETUP_ORACLE and p.notes["setup_mode"] == "agent"
    e = a.env_plan(tmp_path, ["src/x.c"])
    assert e.oracle == "" and e.notes["no_upstream_oracle"] and e.image == "buildpack-deps:bookworm"
    assert a.is_dep_file("vcpkg.json") and not a.is_dep_file("src/x.c")


FIXTURE_TASK = (Path(__file__).resolve().parents[3] / "testenvs" / "cvepatch-fixture" / "public"
                / "defensive_task.json")


@pytest.fixture
def make_box(tmp_path):
    def make(mode):
        src = write(tmp_path / "src",
                    {"Makefile": "all:\n\techo built > out.txt\ntest:\n\ttest -f out.txt\n"})
        return DefensiveToolbox(source_dir=src, workspace_dir=tmp_path / "ws",
                                task_path=FIXTURE_TASK, mode=mode)
    return make


def test_submit_setup_reruns_commands_on_fresh_tree(make_box):
    box = make_box("setup")
    assert "SETUP task" in box.setup()["instructions"]
    assert box.submit_setup("make all", "make test", "true")["ok"]
    bad = box.submit_setup("true", "make test", "true")       # test needs the build's output
    assert not bad["ok"] and bad["step"] == "test"
    assert not box.submit_setup("", "make test", "true")["ok"]


def test_submit_setup_refused_outside_setup(make_box):
    box = make_box("episode")
    assert not box.submit_setup("make", "make test", "true")["ok"]
    assert "SETUP task" not in box.setup()["instructions"]


def test_leakcheck_finds_fixed_copy(tmp_path):
    base = write(tmp_path / "baseline", {"src/buf.c": "int copy() {\n    if (n > cap) n = cap;\n}\n"})
    root = tmp_path / "root"
    write(root, {"usr/lib/x.so.txt": "unrelated\n"})
    clean = leakcheck.check(FIX_PATCH, base, None, root=str(root))
    assert clean["patterns"] == 2 and not clean["leak"]
    write(root, {"root/fixed/src/buf.c":
                 "    if (n >= capacity_of_destination) n = capacity_of_destination - 1;\n"
                 "    d[n] = '\\0'; /* always terminate the destination buffer */\n"})
    leaked = leakcheck.check(FIX_PATCH, base, None, root=str(root))
    assert leaked["leak"] and leaked["leaked_files"][0]["path"].endswith("fixed/src/buf.c")


def test_leakcheck_ignores_lines_already_in_baseline(tmp_path):
    line = "if (n >= capacity_of_destination) n = capacity_of_destination - 1;"
    base = write(tmp_path / "baseline", {"other.c": line + "\n"})
    assert line not in leakcheck.patterns(FIX_PATCH, base)


def test_leakcheck_finds_git_clone_with_fix(tmp_path):
    repo = tmp_path / "root" / "home" / "proj"
    repo.mkdir(parents=True)

    def g(*a):
        return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True,
                              text=True).stdout.strip()
    g("init", "-q")
    (repo / "f").write_text("x")
    g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fix")
    sha = g("rev-parse", "HEAD")
    assert leakcheck.git_dirs_with(sha, str(tmp_path / "root"))
    assert not leakcheck.git_dirs_with("0" * 40, str(tmp_path / "root"))


def test_last_setup_takes_last_accepted(tmp_path):
    rows = [{"tool": "submit_setup", "args": {}, "result": json.dumps({"ok": False})},
            {"tool": "submit_setup", "args": {}, "result": json.dumps(
                {"ok": True, "build_command": "make", "test_command": "make check"})},
            {"tool": "run_command", "args": {}, "result": "{}"}]
    (tmp_path / "tool_calls.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert agent_setup.last_setup(tmp_path)["test_command"] == "make check"
    assert agent_setup.last_setup(tmp_path / "missing") is None


def test_write_hidden_fills_commands_and_oracle(tmp_path):
    (tmp_path / "hidden" / "oracle").mkdir(parents=True)
    (tmp_path / "hidden" / "task.json").write_text(json.dumps({
        "build_instructions": {"command": ["true"]}, "existing_test_command": None,
        "limitations": ["No sibling tests found; existing-test check not run."],
        "metadata": {"has_oracle": True}}))
    agent_setup.write_hidden(tmp_path, "./configure && make", "make check",
                             {"build_command": "./configure && make", "test_command": "make check"})
    t = json.loads((tmp_path / "hidden" / "task.json").read_text())
    assert t["build_instructions"]["command"] == ["bash", "-c", "./configure && make"]
    assert t["existing_test_command"]["command"] == ["bash", "-c", "make check"]
    assert not any(x.startswith("No sibling") for x in t["limitations"])
    sh = (tmp_path / "hidden" / "oracle" / "setup_cmd.sh").read_text()
    assert "( ./configure && make ) && ( make check )" in sh


def test_reset_dockerfile_restores_trusted_paths():
    df = agent_setup.RESET_DOCKERFILE.format(base="b", raw="r", cmd=agent_setup.MCP_CMD)
    for p in ("/rlenv/src", "/opt/defensive", "/opt/pkg", "/opt/venv", "/opt/vpy"):
        assert f"COPY --from=base {p} {p}" in df
    assert "USER agent" in df and "DEF_MODE=episode" in df


def test_bundle_marks_setup_mode(tmp_path):
    """A native bundle from a tiny C repo: no commands yet, oracle via setup_cmd.sh."""
    repo = tmp_path / "cache" / "acme__clib"
    write(repo, {"Makefile": "all:\n\tcc -c src/buf.c\n", "src/buf.c": "int f(int n){return n;}\n",
                 "tests/test_buf.c": "int main(void){return 0;}\n"})

    def g(*a):
        return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True,
                              text=True).stdout.strip()
    g("init", "-q")
    g("-c", "user.email=t@t", "-c", "user.name=t", "add", "-A")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "vuln")
    (repo / "src" / "buf.c").write_text("int f(int n){return n < 0 ? 0 : n;}\n")
    (repo / "tests" / "test_buf.c").write_text("int main(void){return 1;}\n")
    g("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "fix")
    sha = g("rev-parse", "HEAD")
    meta = core.build_task("CVE-2099-0003", f"https://github.com/acme/clib/commit/{sha}",
                           tmp_path / "cache", tmp_path / "out", ADAPTERS["native"])
    out = tmp_path / "out" / meta["task_id"]
    task = json.loads((out / "hidden" / "task.json").read_text())
    assert meta["setup_mode"] == "agent" and meta["has_oracle"]
    assert "setup_cmd.sh" in (out / "hidden" / "oracle" / "run.sh").read_text()
    assert "FROM buildpack-deps:bookworm" in (out / "Dockerfile").read_text()
    assert task["metadata"]["ecosystem"] == "native"
    assert task["metadata"]["setup_mode"] == "agent"   # what agent_setup.py + confirm read


def test_cpu_list_parsing_skips_reserved_cores():
    import taskgen_confirm
    cpus = taskgen_confirm.parse_cpu_list("0-3,6-11,14-17\n")
    assert cpus[:8] == [0, 1, 2, 3, 6, 7, 8, 9] and 4 not in cpus
    assert taskgen_confirm.parse_cpu_list("") == []


def test_unusable_upstream_test_is_demoted_not_dropped(tmp_path, monkeypatch):
    import taskgen_confirm
    b = tmp_path / "go-cve-2099-9"
    (b / "hidden" / "oracle").mkdir(parents=True)
    (b / "hidden" / "oracle" / "run.sh").write_text("exit 3")
    (b / "hidden" / "task.json").write_text(json.dumps(
        {"metadata": {"has_oracle": True}, "regression_test_command": {"command": ["bash", "x"]}}))
    monkeypatch.setattr(taskgen_confirm, "_build_check", lambda *a: {"status": "INCONCLUSIVE"})
    assert taskgen_confirm.demote_oracle(b, "img", "why") is None          # fix doesn't build
    assert (b / "hidden" / "oracle").is_dir()
    monkeypatch.setattr(taskgen_confirm, "_build_check", lambda *a: {"status": "BUILDABLE"})
    r = taskgen_confirm.demote_oracle(b, "img", "oracle tests do not compile")
    t = json.loads((b / "hidden" / "task.json").read_text())
    assert r["status"] == "BUILDABLE" and not (b / "hidden" / "oracle").exists()
    assert (b / "hidden" / "oracle.unusable" / "run.sh").is_file()
    assert t["metadata"]["has_oracle"] is False and t["regression_test_command"]["command"] == ["true"]


def test_cpu_slice_differs_per_job_index(monkeypatch, tmp_path):
    import taskgen_confirm
    f = tmp_path / "cpus"
    f.write_text("0-3,6-11,14-41\n")
    monkeypatch.setattr(taskgen_confirm, "DIND_CPUS", f)
    picks = []
    for idx in ("0", "1", "2"):
        monkeypatch.setenv("JOB_COMPLETION_INDEX", idx)
        picks.append(taskgen_confirm.cpu_args()[1])
    assert picks[0] == "0,1,2,3,6,7,8,9" and len(set(picks)) == 3


def test_submit_setup_checks_install_script(make_box):
    box = make_box("setup")
    assert "install_script is required" in box.submit_setup("make all", "make test", "")["error"]
    bad = box.submit_setup("make all", "make test", "if then fi")
    assert not bad["ok"] and bad["step"] == "install" and "syntax" in bad["error"]
    failing = box.submit_setup("make all", "make test", "echo installing; exit 3")
    assert not failing["ok"] and failing["step"] == "install" and failing["exitcode"] == 3
    ok = box.submit_setup("make all", "make test", "test -f Makefile  # runs in a source copy")
    assert ok["ok"] and ok["install_script"].startswith("test -f Makefile")


def _setup_bundle(root: Path, task_id: str, repo: str = "https://github.com/acme/clib") -> Path:
    b = root / task_id
    (b / "hidden").mkdir(parents=True)
    (b / "hidden" / "task.json").write_text(json.dumps({
        "cve_id": task_id.upper(), "source_repository": repo, "fixed_commit": "f" * 40,
        "vulnerable_commit": "a" * 40, "build_instructions": {"command": ["true"]},
        "existing_test_command": None, "limitations": [],
        "metadata": {"setup_mode": "agent", "ecosystem": "native", "has_oracle": False}}))
    return b


RECIPE = {"install_script": "apt-get install -y libfoo-dev", "build_command": "make",
          "test_command": "make check"}


def test_recipe_store_round_trip(tmp_path):
    import argparse
    a = argparse.Namespace(recipes=tmp_path / "recipes")
    b1 = _setup_bundle(tmp_path, "native-cve-2099-1")
    task = json.loads((b1 / "hidden" / "task.json").read_text())
    agent_setup.save_recipe(a, b1, task, {**RECIPE, "notes": "n"})
    assert json.loads((b1 / "setup_recipe.json").read_text())["build_command"] == "make"
    got = agent_setup.repo_recipes(a, task)
    assert len(got) == 1 and got[0]["task_id"] == "native-cve-2099-1"
    other = json.loads(_setup_bundle(tmp_path, "native-cve-2099-9", "https://github.com/x/y")
                       .joinpath("hidden", "task.json").read_text())
    assert agent_setup.repo_recipes(a, other) == []          # different repo


def test_setup_reuses_a_repo_recipe_without_an_episode(tmp_path, monkeypatch):
    import argparse
    a = argparse.Namespace(recipes=tmp_path / "recipes", model="m", turns=5, timeout=60,
                           no_langfuse=True)
    b1 = _setup_bundle(tmp_path, "native-cve-2099-1")
    agent_setup.save_recipe(a, b1, json.loads((b1 / "hidden" / "task.json").read_text()), RECIPE)
    b2 = _setup_bundle(tmp_path, "native-cve-2099-2")
    monkeypatch.setattr(agent_setup, "build_base", lambda b, base: None)
    built = []

    def fake_from_recipe(bundle, base, final, recipe, task):
        built.append((bundle.name, recipe["build_command"]))
        return {"status": "SETUP_OK", "image": final, "recipe": True}
    monkeypatch.setattr(agent_setup, "from_recipe", fake_from_recipe)
    monkeypatch.setattr(agent_setup, "run_setup_episode",
                        lambda *a_, **k: (_ for _ in ()).throw(AssertionError("no episode")))
    r = agent_setup.setup_one(b2, a)
    assert r["status"] == "SETUP_OK" and r["reused_from"] == "native-cve-2099-1"
    assert built == [("native-cve-2099-2", "make")] and (b2 / "setup_recipe.json").is_file()


def test_from_recipe_checks_offline_and_leaks(tmp_path, monkeypatch):
    b = _setup_bundle(tmp_path, "native-cve-2099-3")
    task = json.loads((b / "hidden" / "task.json").read_text())
    import subprocess as sp
    monkeypatch.setattr(agent_setup, "sh", lambda cmd, timeout, **kw: sp.CompletedProcess(cmd, 0, "", ""))
    monkeypatch.setattr(agent_setup, "offline_check", lambda *a: (False, "make: *** Error 2"))
    r = agent_setup.from_recipe(b, "base", "final", RECIPE, task)
    assert r["status"] == "RECIPE_FAILED" and "offline" in r["reason"]
    monkeypatch.setattr(agent_setup, "offline_check", lambda *a: (True, ""))
    monkeypatch.setattr(agent_setup, "leak_check", lambda *a: ("LEAKED", {"leak": True}))
    assert agent_setup.from_recipe(b, "base", "final", RECIPE, task)["status"] == "LEAKED"
    monkeypatch.setattr(agent_setup, "leak_check", lambda *a: (None, {"leak": False}))
    ok = agent_setup.from_recipe(b, "base", "final", RECIPE, task)
    t = json.loads((b / "hidden" / "task.json").read_text())
    assert ok["status"] == "SETUP_OK" and t["existing_test_command"]["command"][-1] == "make check"


def test_root_cause_unwraps_exception_groups():
    inner = TimeoutError("request exceeded 450s")
    e = BaseExceptionGroup("unhandled errors in a TaskGroup", [ExceptionGroup("x", [inner])])
    assert agent_setup.root_cause(e) is inner
    assert agent_setup.root_cause(ValueError("v")).args == ("v",)


def test_refresh_vpy_stage_updates_old_dockerfiles(tmp_path):
    import taskgen_confirm

    from cvepatch.core.taskgen.core import DOCKERFILE
    old = ("FROM python:3.11-slim-bookworm AS vpy\nRUN pip install uv\n\n"
           "FROM golang:1.22\nCOPY baseline/ /opt/defensive/baseline/\n")
    (tmp_path / "Dockerfile").write_text(old)
    taskgen_confirm.refresh_vpy_stage(tmp_path)
    new = (tmp_path / "Dockerfile").read_text()
    assert new.startswith(DOCKERFILE.split("FROM {image}")[0].rstrip("\n"))
    assert "vpy setup failed" in new and new.endswith("FROM golang:1.22\nCOPY baseline/ /opt/defensive/baseline/\n")
    taskgen_confirm.refresh_vpy_stage(tmp_path)                 # idempotent
    assert (tmp_path / "Dockerfile").read_text() == new
