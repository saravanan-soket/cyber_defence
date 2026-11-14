"""scripts/worker.py: sharding and per-task resume, with Docker / LLM stubbed."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))
import worker  # noqa: E402


def bundle(root: Path, task_id: str, setup: bool = False) -> Path:
    b = root / task_id.split("-", 1)[0] / task_id
    (b / "hidden").mkdir(parents=True)
    (b / "hidden" / "task.json").write_text(json.dumps(
        {"metadata": {"setup_mode": "agent"} if setup else {}}))
    return b


@pytest.fixture
def stubs(monkeypatch, tmp_path):
    for k in ("CVEPATCH_DB", "CVEPATCH_RUNS_DIR", "CVEPATCH_HOST"):
        monkeypatch.setenv(k, str(tmp_path / k.lower()))   # work() setdefaults these
    calls = {"setup": 0, "confirm": 0, "run": 0}
    state = {"images": set(), "confirm": "REPRODUCIBLE", "setup": "SETUP_OK"}

    def setup_one(b, a):
        calls["setup"] += 1
        if state["setup"] == "SETUP_OK":
            state["images"].add(b.name)
        return {"status": state["setup"]}

    def confirm(b):
        calls["confirm"] += 1
        state["images"].add(b.name)
        return {"status": state["confirm"]}

    def do_run(b, a, shard_dir, labels=None):
        calls["run"] += 1
        return {"status": "DONE", "tiers": ["T1"]}

    monkeypatch.setattr(worker.agent_setup, "setup_one", setup_one)
    monkeypatch.setattr(worker.taskgen_confirm, "confirm", confirm)
    monkeypatch.setattr(worker.taskgen_confirm, "docker_alive", lambda: True)
    monkeypatch.setattr(worker, "do_run", do_run)
    monkeypatch.setattr(worker, "image_exists", lambda t: t in state["images"])
    monkeypatch.setattr(worker, "prune", lambda t: state["images"].discard(t))
    return calls, state


def args(tmp: Path, **kw):
    ns = dict(tasks=tmp / "tasks", results=tmp / "scale" / "results", index=0, shards=1,
              rows=None, advisories=None, cache=tmp / "cache",
              lang="", limit=0, model="m", setup_model="", recipes=tmp / "recipes",
              keep_all=False, run_all=False, redo_setup=False, c_only=False, no_setup=False, attempts=1, turns=150, setup_turns=80, episode_timeout=60,
              benchmark_id="b", include_buildable=False, no_run=False, retry_failed=False,
              summary=False, timeout=60, no_langfuse=True, final_retry_wait=0, net_wait=0, max_attempts=5)
    ns.update(kw)
    import argparse
    return argparse.Namespace(**ns)


def test_shards_partition_tasks():
    ids = [f"go-cve-2024-{i}" for i in range(200)]
    parts = [{t for t in ids if worker.in_shard(t, i, 7)} for i in range(7)]
    assert set().union(*parts) == set(ids) and sum(map(len, parts)) == len(ids)


def test_full_pipeline_then_skips_when_final(tmp_path, stubs):
    calls, _ = stubs
    bundle(tmp_path / "tasks", "go-cve-2099-1")
    bundle(tmp_path / "tasks", "native-cve-2099-2", setup=True)
    a = args(tmp_path)
    assert worker.work(a) == 0
    assert calls == {"setup": 1, "confirm": 2, "run": 2}
    r = json.loads((a.results / "native-cve-2099-2.json").read_text())
    assert r["setup"]["status"] == "SETUP_OK" and r["run"]["tiers"] == ["T1"] and r["final"]
    worker.work(a)                       # rerun: everything final, nothing redone
    assert calls == {"setup": 1, "confirm": 2, "run": 2}


def test_lost_image_redoes_setup_and_confirm(tmp_path, stubs):
    calls, state = stubs
    b = bundle(tmp_path / "tasks", "native-cve-2099-3", setup=True)
    a = args(tmp_path, no_run=True)
    worker.work(a)                       # setup + confirm, not final (no_run)
    assert calls["setup"] == 1 and calls["confirm"] == 1
    (b / "setup_result.json").write_text(json.dumps({"status": "SETUP_OK"}))
    state["images"].clear()              # pod restarted: node-local images gone
    worker.work(args(tmp_path))
    assert calls["setup"] == 2 and calls["confirm"] == 2 and calls["run"] == 1


def test_unrunnable_confirm_is_final_without_run(tmp_path, stubs):
    calls, state = stubs
    state["confirm"] = "INCONCLUSIVE"
    bundle(tmp_path / "tasks", "go-cve-2099-4")
    a = args(tmp_path)
    worker.work(a)
    r = json.loads((a.results / "go-cve-2099-4.json").read_text())
    assert r["final"] and "run" not in r and calls["run"] == 0


def test_failed_setup_retried_only_with_retry_failed(tmp_path, stubs):
    calls, state = stubs
    state["setup"] = "FAILED"
    bundle(tmp_path / "tasks", "native-cve-2099-5", setup=True)
    worker.work(args(tmp_path, retry_failed=True))
    worker.work(args(tmp_path, retry_failed=True))
    assert calls["setup"] == 2               # left open, retried
    worker.work(args(tmp_path))              # without the flag it becomes final
    worker.work(args(tmp_path))
    assert calls["setup"] == 3


def test_summary_counts(tmp_path, stubs, capsys):
    bundle(tmp_path / "tasks", "go-cve-2099-6")
    a = args(tmp_path)
    worker.work(a)
    worker.summary(a)
    out = json.loads(capsys.readouterr().out)
    assert out["by_lang"]["go"] == {"RUN_DONE": 1} and out["episode_tiers"] == {"T1": 1}


def _row(cve, repo, track="lang:go"):
    return {"cve": cve, "track": track, "fix_refs": [{"repo": repo, "sha": "abcdef1"}]}


def test_rows_mode_shards_by_repo_and_generates_bundles(tmp_path, stubs, monkeypatch):
    calls, _ = stubs
    rows = [_row("CVE-2099-10", "https://github.com/acme/a"),
            _row("CVE-2099-11", "https://github.com/acme/a"),
            _row("CVE-2099-12", "https://github.com/acme/b"),
            _row("CVE-2099-13", "https://git.kernel.org/x", track="linux-kernel"),
            _row("CVE-2099-14", "https://github.com/acme/c")]
    (tmp_path / "rows.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    built = []

    def build_first(row, refs, *, out_root, adapter, **kw):
        if row["cve"] == "CVE-2099-14":
            raise worker.SkipCandidate("fix changes dependency manifests (can't grade offline)")
        b = out_root / f"{adapter.name}-{row['cve'].lower()}"
        (b / "hidden").mkdir(parents=True)
        (b / "hidden" / "task.json").write_text(json.dumps({"metadata": {}}))
        built.append(row["cve"])
        return {}, refs[0]
    monkeypatch.setattr(worker.taskgen, "build_first", build_first)
    monkeypatch.setattr(worker, "has_bundle", lambda b: (b / "hidden" / "task.json").is_file())

    same = {worker.in_shard("acme/a", i, 3) for i in range(3)}
    assert same == {True, False}                        # repo a lives in exactly one shard
    for i in range(3):
        worker.work(args(tmp_path, rows=tmp_path / "rows.jsonl", advisories=None,
                         cache=tmp_path / "cache", shards=3, index=i))
    assert sorted(built) == ["CVE-2099-10", "CVE-2099-11", "CVE-2099-12"]   # kernel row skipped
    res = tmp_path / "scale" / "results"
    skipped = json.loads((res / "go-cve-2099-14.json").read_text())
    assert skipped["taskgen"]["status"] == "UNSUPPORTED" and skipped["final"]
    assert calls["run"] == 3
    for i in range(3):                                  # second pass: nothing regenerated
        worker.work(args(tmp_path, rows=tmp_path / "rows.jsonl", advisories=None,
                         cache=tmp_path / "cache", shards=3, index=i))
    assert len(built) == 3 and calls["run"] == 3


def test_failed_tasks_get_a_second_pass_at_the_end(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    seen = []

    def flaky_confirm(b):
        seen.append(b.name)
        state["images"].add(b.name)
        return {"status": "FAILED" if len(seen) == 1 else "REPRODUCIBLE"}
    monkeypatch.setattr(worker.taskgen_confirm, "confirm", flaky_confirm)
    monkeypatch.setattr(worker.time, "sleep", lambda s: None)
    bundle(tmp_path / "tasks", "go-cve-2099-20")
    worker.work(args(tmp_path, retry_failed=True, final_retry_wait=1))
    r = json.loads((tmp_path / "scale" / "results" / "go-cve-2099-20.json").read_text())
    assert seen == ["go-cve-2099-20", "go-cve-2099-20"] and r["run"]["status"] == "DONE"


def test_wait_for_network_blocks_until_dns_works(monkeypatch):
    tries = []

    def gai(host, port):
        tries.append(host)
        if len(tries) < 3:
            raise OSError("Temporary failure in name resolution")
        return [()]
    monkeypatch.setattr(worker.socket, "getaddrinfo", gai)
    monkeypatch.setattr(worker.time, "sleep", lambda s: None)
    assert worker.wait_for_network(max_wait=600, poll=30) is True and len(tries) >= 3
    monkeypatch.setattr(worker.socket, "getaddrinfo",
                        lambda h, p: (_ for _ in ()).throw(OSError("down")))
    assert worker.wait_for_network(max_wait=60, poll=30) is False


def test_setup_model_and_recipe_rebuild(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    seen = {}

    def setup_one(b, a):
        calls["setup"] += 1
        seen["setup_model"] = a.model
        state["images"].add(b.name)
        (b / "setup_recipe.json").write_text("{}")
        return {"status": "SETUP_OK"}
    monkeypatch.setattr(worker.agent_setup, "setup_one", setup_one)
    rebuilt = []

    def rebuild(b):
        rebuilt.append(b.name)
        state["images"].add(b.name)
        return {"status": "SETUP_OK"}
    monkeypatch.setattr(worker.agent_setup, "rebuild", rebuild)
    b = bundle(tmp_path / "tasks", "native-cve-2099-30", setup=True)
    worker.work(args(tmp_path, no_run=True, model="openai/glm5.3-defense",
                     setup_model="openai/gpt-oss-120b"))
    assert seen["setup_model"] == "openai/gpt-oss-120b" and calls["setup"] == 1
    (b / "setup_result.json").write_text(json.dumps({"status": "SETUP_OK"}))
    state["images"].clear()                       # another pod: image gone, recipe kept
    worker.work(args(tmp_path, model="openai/glm5.3-defense", setup_model="openai/gpt-oss-120b"))
    assert rebuilt == ["native-cve-2099-30"] and calls["setup"] == 1 and calls["run"] == 1
    cfg = worker.run_config("native-cve-2099-30", args(tmp_path, model="openai/glm5.3-defense"))
    assert cfg["models"] == [{"id": "openai/glm5.3-defense"}]


def test_run_all_runs_inconclusive_and_unbuilt_tasks_with_labels(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    got = {}

    def do_run(b, a, shard_dir, labels=None):
        calls["run"] += 1
        got[b.name] = labels
        return {"status": "DONE", "tiers": ["T4"]}
    monkeypatch.setattr(worker, "do_run", do_run)
    monkeypatch.setattr(worker, "use_base_image", lambda t: True)
    state["confirm"] = "INCONCLUSIVE"
    bundle(tmp_path / "tasks", "go-cve-2099-40")
    worker.work(args(tmp_path))                          # default: INCONCLUSIVE is not run
    assert calls["run"] == 0
    worker.work(args(tmp_path, results=tmp_path / "r2", run_all=True))
    assert calls["run"] == 1 and got["go-cve-2099-40"]["confirm"] == "INCONCLUSIVE"
    state["setup"] = "SETUP_FAILED"
    bundle(tmp_path / "tasks", "native-cve-2099-41", setup=True)
    worker.work(args(tmp_path, results=tmp_path / "r3", run_all=True))
    lab = got["native-cve-2099-41"]
    assert lab["env"] == "unbuilt" and lab["setup"] == "SETUP_FAILED" and lab["confirm"] == "SKIPPED"


def test_redo_setup_reruns_a_successful_setup_once(tmp_path, stubs):
    calls, state = stubs
    b = bundle(tmp_path / "tasks", "native-cve-2099-50", setup=True)
    (b / "setup_result.json").write_text(json.dumps({"status": "SETUP_OK"}))
    state["images"].add(b.name)
    worker.work(args(tmp_path, no_run=True))
    assert calls["setup"] == 0                          # earlier success is kept by default
    worker.work(args(tmp_path, results=tmp_path / "r2", no_run=True, redo_setup=True))
    assert calls["setup"] == 1                          # redone in the new run


def test_c_only_skips_other_languages_and_fills_the_limit_with_c(tmp_path, stubs):
    calls, _ = stubs
    for i, files in enumerate((["lib/x.rb"], ["src/a.c"], ["app/m.php"], ["src/b.cpp"], ["src/c.h"])):
        b = bundle(tmp_path / "tasks", f"native-cve-2099-6{i}", setup=True)
        (b / "meta.json").write_text(json.dumps({"patched_files": files}))
    worker.work(args(tmp_path, c_only=True, limit=2, no_run=True))
    res = {p.stem: json.loads(p.read_text()) for p in (tmp_path / "scale" / "results").glob("*.json")}
    done = [k for k, r in res.items() if not r.get("skipped")]
    assert len(done) == 2 and calls["setup"] == 2                 # limit counts C/C++ only
    assert all(r.get("skipped") == "not C/C++" for k, r in res.items() if k not in done)


def test_no_setup_patch_stage_rebuilds_or_runs_unbuilt(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    got = {}
    monkeypatch.setattr(worker, "do_run", lambda b, a, sd, labels=None: (got.__setitem__(b.name, labels), {"status": "DONE", "tiers": ["T4"]})[1])
    monkeypatch.setattr(worker, "use_base_image", lambda t: True)
    monkeypatch.setattr(worker.agent_setup, "build_base", lambda b, base: None)
    monkeypatch.setattr(worker.agent_setup, "rebuild",
                        lambda b: (state["images"].add(b.name), {"status": "SETUP_OK"})[1])
    ok = bundle(tmp_path / "tasks", "native-cve-2099-70", setup=True)
    (ok / "setup_result.json").write_text(json.dumps({"status": "SETUP_OK"}))
    (ok / "setup_recipe.json").write_text("{}")
    bad = bundle(tmp_path / "tasks", "native-cve-2099-71", setup=True)
    (bad / "setup_result.json").write_text(json.dumps({"status": "SETUP_FAILED"}))
    worker.work(args(tmp_path, no_setup=True, run_all=True))
    assert calls["setup"] == 0                                   # never a setup episode
    assert "env" not in got["native-cve-2099-70"]                # rebuilt from its recipe
    assert got["native-cve-2099-71"]["env"] == "unbuilt"


def test_setup_failed_on_a_model_error_is_retried(tmp_path, stubs):
    calls, state = stubs
    b = bundle(tmp_path / "tasks", "native-cve-2099-80", setup=True)
    res = tmp_path / "scale" / "results"
    res.mkdir(parents=True)
    rec = {"task_id": b.name, "lang": "native", "final": True,
           "setup": {"status": "SETUP_FAILED", "reason": "no accepted submit_setup"}}
    (res / f"{b.name}.json").write_text(json.dumps(rec))
    (b / "setup_result.json").write_text(json.dumps({"status": "SETUP_FAILED",
                                                     "exit_reason": "error: InternalServerError"}))
    assert worker.is_failed(rec, b)
    worker.work(args(tmp_path, retry_failed=True, no_run=True))
    assert calls["setup"] == 1                                    # retried
    (b / "setup_result.json").write_text(json.dumps({"status": "SETUP_FAILED",
                                                     "exit_reason": "no_tool_calls"}))
    assert not worker.is_failed({"setup": {"status": "SETUP_FAILED"}}, b)   # a real failure stays


def test_failed_task_gets_at_most_max_attempts(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    seen = []
    monkeypatch.setattr(worker.taskgen_confirm, "confirm", lambda b: (seen.append(1), {"status": "FAILED"})[1])
    bundle(tmp_path / "tasks", "go-cve-2099-90")
    for _ in range(7):
        worker.work(args(tmp_path, retry_failed=True, max_attempts=3))
    assert len(seen) == 3


def test_lost_network_exits_so_the_pod_is_replaced(tmp_path, stubs, monkeypatch):
    calls, state = stubs
    bundle(tmp_path / "tasks", "go-cve-2099-91")
    monkeypatch.setattr(worker, "wait_for_network", lambda t: False)
    assert worker.work(args(tmp_path, net_wait=300)) == 75 and calls["confirm"] == 0
