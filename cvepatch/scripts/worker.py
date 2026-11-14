#!/usr/bin/env python3
"""One shard of the scaled pipeline: every task end to end, in one pod.

Each pod of the Indexed Job (deploy/kube/cvepatch-workers.yaml) has its own
Docker daemon and image store on the node's local disk, so pods share
nothing but the repo (bundles, results) and Langfuse. For each bundle in its
shard, in order:

  0. taskgen            with --rows (triage rows): clone + write the bundle.
                        Sharded by repository, so all CVEs of a repo land in one
                        pod (its clone is reused; no two pods write one clone).
                        Without --rows: the bundles already under --tasks,
                        sharded by task id.
  1. agent setup        setup-mode bundles only (scripts/agent_setup.py)
  2. confirm            build + verify the reference solution offline
  3. run                REPRODUCIBLE (and BUILDABLE with --include-buildable):
                        register in this shard's DB, GLM episodes (`--attempts`
                        seeds) via `cvepatch benchmark`, verified, posted to
                        Langfuse by the orchestrator
  4. prune              drop the task's images so the store stays small

Progress is one JSON per task in <results>/<task_id>.json, written after
every stage, so a restarted pod resumes where it stopped.

  python scripts/worker.py --tasks runs/defensive-tasks --results runs/scale/results \
      --index $JOB_COMPLETION_INDEX --shards 20
  python scripts/worker.py --tasks runs/defensive-tasks --results runs/scale/results --summary
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_setup  # noqa: E402
import taskgen  # noqa: E402
import taskgen_confirm  # noqa: E402
import yaml  # noqa: E402

from cvepatch.core.taskgen.commit_ref import repo_slug  # noqa: E402
from cvepatch.core.taskgen.core import SkipCandidate, bundle_complete  # noqa: E402
from cvepatch.core.taskgen.languages import ADAPTERS  # noqa: E402

FIXTURE = REPO / "benchmarks" / "cvepatch-fixture-glm53.yaml"
RUNNABLE = {"REPRODUCIBLE", "BUILDABLE"}
C_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
         ".m", ".mm"}


def is_c_task(b: Path) -> bool:
    """Does the fix touch C/C++ code? ("native" also holds Ruby, PHP... projects.)"""
    meta = load(b / "meta.json")
    files = (meta.get("patched_files") or []) + (meta.get("oracle_files") or [])
    return any(Path(f).suffix.lower() in C_EXT for f in files)
SETUP_LANGS = {"native", "dotnet", "elixir"}


def bundles_of(tasks: Path) -> list[Path]:
    return sorted({tj.parent.parent for tj in tasks.glob("*/*/hidden/task.json")}
                  | {tj.parent.parent for tj in tasks.glob("*/hidden/task.json")})


# Kernel / Android trees need a VM or an AOSP build, not a container (own
# tracks, not built yet); their GitHub mirrors would otherwise land in "native".
SKIP_REPO_RE = re.compile(r"(^|/)torvalds/linux$|^git\.kernel\.org/|^android\.googlesource\.com/"
                          r"|^source\.codeaurora\.org/|(^|/)android/(kernel|platform)")
# A repo with more CVEs than this is split into parts (each its own shard key and
# its own clone), so one huge repo does not leave a single pod running for weeks.
PART_SIZE = 100


def items_from_rows(rows: Path, langs: set[str], cache: Path) -> list[tuple[str, dict, object, Path]]:
    """(shard key, triage row, adapter, clone cache) for every CVE an adapter covers."""
    by_track = {ad.track: ad for ad in ADAPTERS.values()}
    found = []
    with rows.open() as fh:
        for ln in fh:
            r = json.loads(ln)
            ad = by_track.get(r.get("track"))
            if ad is None or (langs and ad.name not in langs):
                continue
            refs = taskgen.commit_refs(r)
            if refs and not SKIP_REPO_RE.search(slug := repo_slug(refs[0].repo)):
                found.append((slug, r, ad))
    per_repo = Counter(slug for slug, _, _ in found)
    out = []
    for slug, r, ad in found:
        parts = -(-per_repo[slug] // PART_SIZE)
        if parts == 1:
            out.append((slug, r, ad, cache))
        else:
            part = zlib.crc32(r["cve"].encode()) % parts
            out.append((f"{slug}#{part}", r, ad, cache / f"part-{part}"))
    return out


def advisories_for(path: Path, cves: set[str]) -> dict[str, dict]:
    """Advisory text for this shard's CVEs only (the file is ~140 MB)."""
    out: dict[str, dict] = {}
    if not path.is_file():
        return out
    with path.open() as fh:
        for ln in fh:
            d = json.loads(ln)
            if d.get("cve_id") in cves:
                out[d["cve_id"]] = d
    return out


def pack(sizes: Counter, shards: int) -> dict[str, int]:
    """key -> shard: largest first onto the least-loaded shard. Deterministic, so
    every pod computes the same assignment from the same rows."""
    load = [(0, i) for i in range(shards)]
    out = {}
    for key, n in sorted(sizes.items(), key=lambda kv: (-kv[1], kv[0])):
        total, i = min(load)
        out[key] = i
        load[i] = (total + n, i)
    return out


def in_shard(task_id: str, index: int, shards: int) -> bool:
    return zlib.crc32(task_id.encode()) % shards == index


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def save(path: Path, rec: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(rec, indent=2) + "\n")
    tmp.replace(path)


def run_config(task_id: str, a: argparse.Namespace) -> dict:
    base = yaml.safe_load(FIXTURE.read_text())
    return {**base, "benchmark_id": a.benchmark_id, "models": [{"id": a.model}],
            "envs": [{"id": f"defensive-{task_id}", "image": f"local/defensive-{task_id}:latest",
                      "task_type": "binary_patch",
                      "interface": "rl.mcp.vulnerability_defense.v1"}],
            "seeds": list(range(1, a.attempts + 1)), "max_parallel": a.attempts,
            "episode_timeout_s": a.episode_timeout,
            "budgets": {**base["budgets"], "turn_budget": a.turns}}


def episode_tiers(runs_dir: Path, benchmark_id: str, env_id: str, since: float) -> list[str]:
    """Verifier tiers of this env's episodes that finished after `since`."""
    tiers = []
    for g in (runs_dir / benchmark_id).glob("*/*/*/grade_calls.jsonl"):
        if g.stat().st_mtime < since or env_id not in (g.parent / "job.json").read_text(errors="replace"):
            continue
        last = g.read_text().strip().splitlines()[-1:] or ["{}"]
        try:
            rec = json.loads(last[0])
        except ValueError:
            continue
        tiers.append(rec.get("tier") or (rec.get("result") or {}).get("tier") or "?")
    return tiers


def do_run(bundle: Path, a: argparse.Namespace, shard_dir: Path,
           labels: dict | None = None) -> dict:
    """Register the env in this shard's DB and run its GLM episodes."""
    task_id = bundle.name
    # The orchestrator's Langfuse sync tags each trace with these (filter later).
    env = {**os.environ, "CVEPATCH_TRACE_LABELS": json.dumps(labels or {})}
    r = subprocess.run(["cvepatch", "register-defensive", str(bundle / "env_manifest.yaml")],
                       capture_output=True, text=True, env=env, timeout=120)
    if r.returncode != 0:
        return {"status": "FAILED", "reason": f"register failed: {r.stderr[-300:]}"}
    cfg = shard_dir / "configs" / f"{task_id}.yaml"
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(yaml.safe_dump(run_config(task_id, a), sort_keys=False))
    t0 = time.time()
    with (shard_dir / "console.log").open("a") as log:
        p = subprocess.run(["cvepatch", "benchmark", "--config", str(cfg), "--retry-failed"],
                           stdout=log, stderr=subprocess.STDOUT, env=env,
                           timeout=a.episode_timeout * a.attempts + 1800)
    tiers = episode_tiers(Path(env["CVEPATCH_RUNS_DIR"]), a.benchmark_id,
                          f"defensive-{task_id}", t0)
    return {"status": "DONE" if tiers else "FAILED", "exit_code": p.returncode,
            "episodes": len(tiers), "tiers": tiers, "minutes": round((time.time() - t0) / 60, 1),
            **({} if tiers else {"reason": "no graded episode (see console.log)"})}


def prune(task_id: str) -> None:
    for tag in ("latest", "base"):
        taskgen_confirm.sh(["docker", "rmi", "-f", f"local/defensive-{task_id}:{tag}"], timeout=300)
    taskgen_confirm.sh(["docker", "builder", "prune", "-af"], timeout=600)
    taskgen_confirm.sh(["docker", "image", "prune", "-f"], timeout=600)


def image_exists(task_id: str) -> bool:
    return taskgen_confirm.sh(["docker", "image", "inspect", f"local/defensive-{task_id}:latest"],
                              timeout=60).returncode == 0


def has_bundle(b: Path) -> bool:
    try:
        return bundle_complete(b)
    except OSError:
        return False


def make_bundle(b: Path, rec: dict, gen: tuple, a: argparse.Namespace) -> bool:
    """Stage 0: clone + write the bundle from its triage row. True if it exists."""
    if has_bundle(b):
        return True
    row, ad, advisory, cache = gen
    try:
        _, used = taskgen.build_first(row, taskgen.commit_refs(row), cache=cache,
                                      out_root=a.tasks / ad.name, adapter=ad, reuse=True,
                                      advisory=advisory, keep_all=a.keep_all)
        rec["taskgen"] = {"status": "CLASSIFIED", "commit": f"{used.repo}@{used.sha}"}
        return True
    except SkipCandidate as e:
        rec["taskgen"] = {"status": taskgen.status_for(str(e)), "reason": str(e)[:300]}
    except Exception as e:  # noqa: BLE001
        rec["taskgen"] = {"status": "FAILED", "reason": f"{type(e).__name__}: {e}"[:300]}
    rec["final"] = rec["taskgen"]["status"] != "FAILED" or not a.retry_failed
    return False


def process(b: Path, rec: dict, out: Path, a: argparse.Namespace, shard_dir: Path,
            gen: tuple | None = None) -> None:
    """Advance one task as far as it goes; `rec` is updated and saved after each stage.
    Images live only in this pod, so a stage whose image is gone (pod restart) is redone."""
    if gen is not None and not make_bundle(b, rec, gen, a):
        return
    if a.c_only and not is_c_task(b):
        rec.update(skipped="not C/C++", final=True)
        return "skipped"
    save(out, rec)
    task = load(b / "hidden" / "task.json")
    if a.run_all:      # every task with an image gets a patch episode; confirm is a label
        want = RUNNABLE | {"INCONCLUSIVE"}
    else:
        want = RUNNABLE if a.include_buildable else {"REPRODUCIBLE"}
    have_image = image_exists(b.name)
    labels = dict(task.get("metadata", {}).get("labels") or {})

    setup_ok = load(b / "setup_result.json").get("status") == "SETUP_OK" and not (
        a.redo_setup and not rec.get("setup"))     # --redo-setup: once per task in this run
    if task.get("metadata", {}).get("setup_mode") == "agent" and setup_ok and not have_image \
            and (b / "setup_recipe.json").is_file():
        # Set up in another pod or an earlier run: rebuild from the recipe, no LLM.
        r = agent_setup.rebuild(b)
        rec["setup_rebuilt"] = r["status"]
        have_image = r["status"] == "SETUP_OK"
    if task.get("metadata", {}).get("setup_mode") == "agent" and not (have_image and setup_ok) \
            and a.no_setup:
        # Patch stage over tasks set up earlier: never run a setup episode here.
        # No working environment -> the patch episode runs on the bare base image.
        failed = agent_setup.build_base(b, f"local/defensive-{b.name}:base")
        if failed or not use_base_image(b.name):
            rec["setup_rebuilt"] = (failed or {}).get("reason", "could not tag base image")
            rec["final"] = not a.retry_failed
            return
        labels["env"] = "unbuilt"
        rec["confirm"] = {"status": "SKIPPED", "reason": "no setup image (setup failed earlier)"}
        save(out, rec)
        return run_step(b, rec, a, shard_dir, labels)
    if task.get("metadata", {}).get("setup_mode") == "agent" and not (have_image and setup_ok):
        s = agent_setup.setup_one(b, argparse.Namespace(**{
            **vars(a), "model": a.setup_model or a.model, "turns": a.setup_turns}))
        save(b / "setup_result.json", s)
        rec["setup"] = {k: s.get(k) for k in ("status", "reason", "turns", "model", "recipe",
                                              "reused_from", "recipe_failure", "exit_reason")
                        if k in s}
        rec.pop("confirm", None)          # a new setup image needs a new confirmation
        save(out, rec)
        if s["status"] == "FAILED" or (s["status"] != "SETUP_OK" and not a.run_all):
            rec["final"] = s["status"] != "FAILED" or not a.retry_failed
            return
        if s["status"] != "SETUP_OK":
            # No working environment: the patch episode still runs, on the clean
            # base image (toolchain + vulnerable source, nothing built).
            if not use_base_image(b.name):
                rec["final"] = not a.retry_failed
                return
            labels["env"] = "unbuilt"
            rec["confirm"] = {"status": "SKIPPED", "reason": f"setup {s['status']}"}
            save(out, rec)
            return run_step(b, rec, a, shard_dir, labels)
        have_image = True

    if (rec.get("confirm") or {}).get("status") not in want or not have_image:
        c = taskgen_confirm.confirm(b)
        rec["confirm"] = {k: c.get(k) for k in ("status", "reason", "tier", "build_s")}
        save(out, rec)
    if rec["confirm"]["status"] not in want:
        rec["final"] = rec["confirm"]["status"] != "FAILED" or not a.retry_failed
        return
    run_step(b, rec, a, shard_dir, labels)


def use_base_image(task_id: str) -> bool:
    """Tag the setup base image as the task image (setup produced none)."""
    return taskgen_confirm.sh(["docker", "tag", f"local/defensive-{task_id}:base",
                               f"local/defensive-{task_id}:latest"], timeout=60).returncode == 0


def run_step(b: Path, rec: dict, a: argparse.Namespace, shard_dir: Path, labels: dict) -> None:
    if a.no_run:
        return
    labels = {**labels, "confirm": (rec.get("confirm") or {}).get("status"),
              **({"setup": rec["setup"].get("status"),
                  "setup_model": rec["setup"].get("model")} if rec.get("setup") else {})}
    rec["labels"] = {k: v for k, v in labels.items() if v is not None}
    rec["run"] = do_run(b, a, shard_dir, rec["labels"])
    rec["final"] = rec["run"]["status"] == "DONE" or not a.retry_failed


def work(a: argparse.Namespace) -> int:
    shard_dir = a.results.parent / f"shard-{a.index:03d}"
    shard_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CVEPATCH_DB", str(shard_dir / "db.sqlite"))
    os.environ.setdefault("CVEPATCH_RUNS_DIR", str(a.results.parent / "runs"))
    os.environ.setdefault("CVEPATCH_HOST", f"shard-{a.index:03d}")
    # The shared clone cache belongs to the user who made it; pods run as root,
    # and git refuses repos owned by someone else ("dubious ownership").
    os.environ.setdefault("GIT_CONFIG_COUNT", "1")
    os.environ.setdefault("GIT_CONFIG_KEY_0", "safe.directory")
    os.environ.setdefault("GIT_CONFIG_VALUE_0", "*")
    a.results.mkdir(parents=True, exist_ok=True)
    langs = {x for x in a.lang.split(",") if x}
    mine: list[tuple[Path, tuple | None]]
    if a.rows:
        allitems = items_from_rows(a.rows, langs, a.cache)
        where = pack(Counter(k for k, _, _, _ in allitems), a.shards)
        items = [it for it in allitems if where[it[0]] == a.index]
        advs = advisories_for(a.advisories or a.rows.parent / "advisories.jsonl",
                              {r["cve"] for _, r, _, _ in items})
        # Builder languages first (cheaper, higher yield), then agent-setup ones.
        items.sort(key=lambda it: (it[2].name in SETUP_LANGS, it[1]["cve"]))
        mine = [(a.tasks / ad.name / f"{ad.name}-{r['cve'].lower()}",
                 (r, ad, advs.get(r["cve"]), cache)) for _, r, ad, cache in items]
    else:
        mine = [(b, None) for b in bundles_of(a.tasks) if in_shard(b.name, a.index, a.shards)
                and (not langs or b.name.split("-", 1)[0] in langs)]
    if a.limit:
        # A pilot should look like the whole run: a stable random sample across
        # languages and years, not the oldest builder-language CVEs. With
        # --c-only the limit counts C/C++ tasks (others are skipped on the way).
        mine = sorted(mine, key=lambda m: zlib.crc32(m[0].name.encode()))
        if not a.c_only:
            mine = mine[: a.limit]
    print(f"shard {a.index}/{a.shards}: {len(mine)} tasks", file=sys.stderr, flush=True)
    rc = run_pass(mine, a, shard_dir)
    if rc == 0 and a.retry_failed and a.final_retry_wait:
        # Network failures come in bursts; give FAILED tasks one more go after the rest.
        again = [m for m in mine if is_failed(load(a.results / f"{m[0].name}.json"), m[0])]
        if again:
            print(f"retrying {len(again)} FAILED tasks in {a.final_retry_wait}s", file=sys.stderr,
                  flush=True)
            time.sleep(a.final_retry_wait)
            rc = run_pass(again, a, shard_dir)
    return rc


NET_HOSTS = ("github.com", "registry-1.docker.io")


def wait_for_network(max_wait: int, poll: int = 30) -> bool:
    """Block while DNS is down (it fails in outages of minutes to hours here), so a
    worker does not burn its tasks as FAILED. True once the hosts resolve again."""
    waited = 0
    while True:
        try:
            for h in NET_HOSTS:
                socket.getaddrinfo(h, 443)
            if waited:
                print(f"network back after {waited}s", file=sys.stderr, flush=True)
            return True
        except OSError:
            if waited >= max_wait:
                print(f"network still down after {waited}s; continuing", file=sys.stderr, flush=True)
                return False
            if waited == 0:
                print("DNS is down; waiting for it", file=sys.stderr, flush=True)
            time.sleep(poll)
            waited += poll


def is_failed(rec: dict, bundle: Path | None = None) -> bool:
    """An infrastructure failure, worth retrying. A setup recorded as SETUP_FAILED
    whose episode died on a model-service error counts too (older records)."""
    if any((rec.get(k) or {}).get("status") == "FAILED"
           for k in ("taskgen", "setup", "confirm", "run")):
        return True
    if (rec.get("setup") or {}).get("status") == "SETUP_FAILED" and bundle is not None:
        exit_reason = load(bundle / "setup_result.json").get("exit_reason") or ""
        return exit_reason.startswith("error:")
    return False


def run_pass(mine: list, a: argparse.Namespace, shard_dir: Path) -> int:
    counted = 0
    for i, (b, gen) in enumerate(mine, 1):
        if a.c_only and a.limit and counted >= a.limit:
            break
        out = a.results / f"{b.name}.json"
        rec = load(out) or {"task_id": b.name, "lang": b.name.split("-", 1)[0]}
        if rec.get("skipped"):
            continue
        if rec.get("final") and not (a.retry_failed and is_failed(rec, b)):
            continue
        if is_failed(rec, b) and rec.get("attempts", 0) >= a.max_attempts:
            continue                       # gave it --max-attempts tries already
        rec.pop("error", None)
        if a.net_wait and not wait_for_network(a.net_wait):
            # This pod has lost its network (seen when nodes failed): exit so the Job
            # starts a new pod, which resumes from the saved per-task results.
            print("no network; exiting so this shard moves to a new pod", file=sys.stderr,
                  flush=True)
            return 75
        rec["attempts"] = rec.get("attempts", 0) + 1
        try:
            if process(b, rec, out, a, shard_dir, gen) != "skipped":
                counted += 1
        except Exception as e:  # noqa: BLE001 - record and move on
            rec["error"] = f"{type(e).__name__}: {e}"[:300]
        save(out, rec)
        prune(b.name)
        stage = rec.get("run") or rec.get("confirm") or rec.get("setup") or rec.get("taskgen") or {}
        print(f"[{i}/{len(mine)}] {b.name}: {stage.get('status')} {stage.get('tiers', '')}",
              file=sys.stderr, flush=True)
        if not taskgen_confirm.docker_alive():
            print("docker daemon is gone; stopping (the pod restart resumes)", file=sys.stderr)
            return 1
    return 0


def summary(a: argparse.Namespace) -> int:
    rows = [load(p) for p in sorted(a.results.glob("*.json"))]
    by = defaultdict(Counter)
    tiers = Counter()
    for r in rows:
        st = (r.get("run") or {}).get("status") and "RUN_" + r["run"]["status"] \
            or (r.get("confirm") or {}).get("status") or (r.get("setup") or {}).get("status") \
            or (r.get("taskgen") or {}).get("status") \
            or ("ERROR" if r.get("error") else "PENDING")
        by[r.get("lang", "?")][st] += 1
        tiers.update((r.get("run") or {}).get("tiers") or [])
    print(json.dumps({"tasks": len(rows), "by_lang": {k: dict(v) for k, v in sorted(by.items())},
                      "episode_tiers": dict(tiers)}, indent=2))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tasks", type=Path, required=True)
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--rows", type=Path, default=None,
                    help="cve_triage.jsonl: generate bundles too (sharded by repository)")
    ap.add_argument("--advisories", type=Path, default=None, help="default: next to --rows")
    ap.add_argument("--cache", type=Path, default=REPO.parent / "taskgen_cache" / "git",
                    help="git clone cache (shared; sharding by repo keeps writers apart)")
    ap.add_argument("--index", type=int, default=int(os.environ.get("JOB_COMPLETION_INDEX", 0)))
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--lang", default="", help="comma-separated filter")
    ap.add_argument("--limit", type=int, default=0, help="first N tasks of this shard (pilots)")
    ap.add_argument("--model", default="openai/glm-5.3")
    ap.add_argument("--attempts", type=int, default=1, help="GLM episodes (seeds) per task")
    ap.add_argument("--turns", type=int, default=150, help="turn budget per patch episode")
    ap.add_argument("--setup-turns", type=int, default=80, help="turn budget per setup episode")
    ap.add_argument("--no-setup", action="store_true",
                    help="patch stage: never run setup episodes; tasks set up earlier are rebuilt "
                         "from their recipe, the rest run on the bare base image (env=unbuilt)")
    ap.add_argument("--redo-setup", action="store_true",
                    help="run setup again even where an earlier run succeeded (measuring a model)")
    ap.add_argument("--setup-model", default="",
                    help="model for setup episodes (default: --model), e.g. openai/gpt-oss-120b")
    ap.add_argument("--recipes", type=Path, default=None,
                    help="per-repo setup recipe store (default: <tasks>/../setup-recipes)")
    ap.add_argument("--episode-timeout", type=int, default=5400)
    ap.add_argument("--benchmark-id", default="cvepatch-glm53-scale")
    ap.add_argument("--include-buildable", action="store_true",
                    help="also run tasks with no upstream test (tier <= T2)")
    ap.add_argument("--no-run", action="store_true", help="setup + confirm only")
    ap.add_argument("--c-only", action="store_true",
                    help="only tasks whose fix touches C/C++ files (others skipped, labelled)")
    ap.add_argument("--keep-all", action="store_true",
                    help="never drop a CVE for being hard to grade; label it instead")
    ap.add_argument("--run-all", action="store_true",
                    help="a patch episode for every task with an image (INCONCLUSIVE too; "
                         "failed setups run on the bare base image), labelled for filtering")
    ap.add_argument("--retry-failed", action="store_true",
                    help="leave FAILED (infra) results open so a later pass retries them")
    ap.add_argument("--final-retry-wait", type=int, default=600,
                    help="with --retry-failed: seconds to wait before re-running FAILED tasks once "
                         "more at the end of the shard (0 = no second pass)")
    ap.add_argument("--net-wait", type=int, default=300,
                    help="before each task, wait up to this many seconds for DNS; if it is still "
                         "down, exit so the Job moves the shard to a new pod (0 = off)")
    ap.add_argument("--max-attempts", type=int, default=5,
                    help="tries per task for infrastructure failures (FAILED)")
    ap.add_argument("--summary", action="store_true")
    # agent_setup.setup_one options
    ap.add_argument("--timeout", type=int, default=5400, help="seconds per setup episode")
    ap.add_argument("--no-langfuse", action="store_true")
    a = ap.parse_args()
    a.recipes = a.recipes or a.tasks.parent / "setup-recipes"
    return summary(a) if a.summary else work(a)


if __name__ == "__main__":
    raise SystemExit(main())
