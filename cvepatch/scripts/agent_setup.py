#!/usr/bin/env python3
"""Container step for setup-mode bundles: an agent builds the environment.

Runs where `docker` is available (a DinD worker pod). For every bundle whose
task has metadata.setup_mode == "agent" and no setup result:

  1. build the base image (toolchain + vulnerable source + MCP server);
  2. reuse: if another CVE of the same repository has a working RECIPE
     (install_script + build_command + test_command), try it first; no LLM;
  3. otherwise run a SETUP episode (network on, root, DEF_MODE=setup) with
     --model (e.g. gpt-oss-120b). The agent reports a recipe with
     submit_setup(), which re-runs the install script as root and build/test
     as `agent` on a fresh copy of the source;
  4. build the task image FROM THE RECIPE (base + install script; nothing from
     the session), run build + tests offline in it, leak-check it (the
     upstream fix's added lines or fix commit anywhere -> rejected). A recipe
     that does not reproduce falls back to the committed session container,
     reset to the vulnerable tree (usable in this pod only);
  5. write the commands into hidden/task.json (+ hidden/oracle/setup_cmd.sh),
     save the recipe in the bundle and in the per-repo store.

rebuild() recreates a task image from its saved recipe in another pod.
The setup trace goes to Langfuse (cvepatch-setup:<CVE>, tag phase:setup).

  python scripts/agent_setup.py --out runs/defensive-tasks --model openai/gpt-oss-120b
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from taskgen_confirm import MEM, cpu_args, docker_alive, sh, stage_pkg  # noqa: E402

from cvepatch.config import Config  # noqa: E402
from cvepatch.core.taskgen.commit_ref import repo_slug  # noqa: E402
from cvepatch.runner.budget import Budget  # noqa: E402
from cvepatch.runner.langfuse_sync import post_episode  # noqa: E402
from cvepatch.runner.llm.factory import build_client  # noqa: E402
from cvepatch.runner.loop import run_episode  # noqa: E402
from cvepatch.runner.mcp_client import McpDockerSession  # noqa: E402
from cvepatch.runner.transcript import TranscriptWriter  # noqa: E402

SETUP_PROMPT = (
    "You are preparing a build environment for an open-source project. Call setup() "
    "first: it gives the project, its location and the rules. Get the project building "
    "and its existing tests running (you are root and have network), then call "
    "submit_setup(build_command, test_command, install_script, notes). Explain your "
    "reasoning as you go."
)
# The model sometimes ends a turn with "let me check..." and no tool call,
# which would end the episode before submit_setup.
SETUP_EXIT_NUDGE = (
    "You have not called submit_setup successfully yet, so the setup is not saved. "
    "Do not try to reproduce or exploit the vulnerability; that is a later session's job. "
    "As soon as the project builds and its tests run, call submit_setup(build_command, "
    "test_command, install_script, notes). Continue with a tool call now.")
# Every REMINDER_EVERY turns until submit_setup succeeds (long sessions drift).
REMINDER_EVERY = 50
SETUP_REMINDER = (
    "Reminder (turn {turn} of {budget}): the goal is a working setup, not a perfect one. "
    "As soon as the project builds and a passing set of its tests runs, call "
    "submit_setup(build_command, test_command, install_script, notes).")
# Patch-phase tools: never offered during setup.
FIX_TOOLS = frozenset({"submit_fix", "submit_patch", "submit_report", "run_tests",
                       "run_static_analysis"})
MCP_CMD = '["/opt/venv/bin/python", "-m", "cvepatch.core.mcp_server.tools"]'
RECIPE_KEYS = ("install_script", "build_command", "test_command")
# Context limit per request for setup models: gpt-oss-120b (also served as
# gpt-defense) takes 128k input.
SETUP_CONTEXT_LIMIT = {"gpt-oss": 100_000, "gpt-defense": 100_000}

# The task image, built from a recipe: the base image plus the install script,
# run as root with network from a throwaway copy of the source. Nothing from
# the agent's session goes in, so a recipe also rebuilds the image in another
# pod (or for another CVE of the same repo) without an LLM.
RECIPE_DOCKERFILE = """FROM {base}
USER root
COPY install.sh /opt/defensive/setup/install.sh
RUN cp -r /opt/defensive/baseline /tmp/src && cd /tmp/src \\
 && bash -e /opt/defensive/setup/install.sh && cd / && rm -rf /tmp/* /var/tmp/*
COPY setup.json /opt/defensive/task/setup.json
RUN chown -R agent /opt/cache /home/agent 2>/dev/null; chmod -R a+rX /opt/defensive; \\
    chmod -R a-w /rlenv/src
USER agent
WORKDIR /
ENV DEF_MODE=episode
CMD {cmd}
"""

# Fallback when a recipe does not reproduce: the committed session container,
# reset to the vulnerable tree. Usable only in this pod (it is not a recipe).
RESET_DOCKERFILE = """FROM {base} AS base
FROM {raw}
USER root
# Keep what setup installed; drop its workspace and anything it touched in the
# vulnerable tree, the task files or our verifier/MCP code (it ran as root).
RUN rm -rf /rlenv/workspace /rlenv/src /opt/defensive /opt/pkg /opt/venv /opt/vpy \\
      /tmp/* /var/tmp/* /root/.bash_history && mkdir -p /rlenv/workspace
COPY --from=base /rlenv/src /rlenv/src
COPY --from=base /opt/defensive /opt/defensive
COPY --from=base /opt/pkg /opt/pkg
COPY --from=base /opt/venv /opt/venv
COPY --from=base /opt/vpy /opt/vpy
COPY setup.json /opt/defensive/task/setup.json
RUN chown -R agent /rlenv/workspace /opt/cache /home/agent 2>/dev/null; \\
    chmod -R a-w /rlenv/src && chmod -R a+rX /opt/defensive /opt/pkg /opt/vpy /opt/venv
USER agent
WORKDIR /
ENV DEF_MODE=episode
CMD {cmd}
"""


def last_setup(run_dir: Path) -> dict | None:
    """The last accepted submit_setup result in the episode's tool calls."""
    path = run_dir / "tool_calls.jsonl"
    found = None
    if not path.is_file():
        return None
    for ln in path.read_text().splitlines():
        try:
            row = json.loads(ln)
        except ValueError:
            continue
        if row.get("tool") != "submit_setup":
            continue
        res = row.get("result")
        try:
            res = json.loads(res) if isinstance(res, str) else res
        except ValueError:
            continue
        if isinstance(res, dict) and res.get("ok"):
            found = res
    return found


def root_cause(e: BaseException) -> BaseException:
    """The first leaf of an ExceptionGroup (anyio/MCP wrap errors in TaskGroups),
    so a crash reads e.g. 'Timeout: request timed out' instead of 'unhandled errors'."""
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    return e


def context_limit_for(model: str) -> int | None:
    return next((v for k, v in SETUP_CONTEXT_LIMIT.items() if k in model), None)


async def run_setup_episode(image: str, name: str, run_dir: Path, *, model: str, cve: str,
                            turns: int, timeout_s: int) -> tuple[object, object]:
    client = build_client(model, config=Config.from_env())
    args = ("--init", "-i", "--name", name, "--user", "0", "-e", "DEF_MODE=setup",
            "--memory", MEM, *cpu_args(), "--pids-limit", "4096")
    result = None
    try:
        async with McpDockerSession.start(image, extra_docker_args=args,
                                          stderr_path=run_dir / "mcp_stderr.log") as session:
            with TranscriptWriter(run_dir) as tw:
                result = await asyncio.wait_for(run_episode(
                    client=client, mcp_session=session, transcript=tw,
                    budget=Budget(turn_budget=turns, token_budget=None, context_budget=None),
                    init_prompt=SETUP_PROMPT, seed=1, excluded_tools=FIX_TOOLS,
                    safety_identifier=f"setup-{cve}", finish_tool="submit_setup",
                    exit_nudge=SETUP_EXIT_NUDGE, context_limit=context_limit_for(model),
                    reminder=SETUP_REMINDER, reminder_every=REMINDER_EVERY),
                    timeout=timeout_s)
    except Exception:  # noqa: BLE001 - teardown errors after a finished episode are harmless
        if result is None:
            raise
    return client, result


def write_hidden(bundle: Path, build: str, test: str, setup: dict) -> None:
    tpath = bundle / "hidden" / "task.json"
    task = json.loads(tpath.read_text())
    task["build_instructions"]["command"] = ["bash", "-c", build]
    task["existing_test_command"] = {"command": ["bash", "-c", test], "workdir": None,
                                     "timeout_s": 1800}
    task["validation_strategy"] = "regression_plus_existing"
    task["limitations"] = [x for x in task.get("limitations", [])
                           if not x.startswith(("No sibling tests", "Build and test commands"))] + [
        "Build and test commands were found by an agent during environment setup."]
    task["metadata"]["setup"] = {k: setup.get(k) for k in ("build_command", "test_command", "notes")}
    tpath.write_text(json.dumps(task, indent=2) + "\n")
    if task["metadata"].get("has_oracle") and (bundle / "hidden" / "oracle").is_dir():
        (bundle / "hidden" / "oracle" / "setup_cmd.sh").write_text(
            f"#!/usr/bin/env bash\n( {build} ) && ( {test} )\n")


# ------------------------------------------------------------------ recipes
def recipe_dir(a: argparse.Namespace, task: dict) -> Path:
    """One file per working recipe, grouped by repository (one writer per file)."""
    slug = repo_slug(task.get("source_repository") or "unknown").replace("/", "__")
    return Path(a.recipes) / slug


def repo_recipes(a: argparse.Namespace, task: dict, limit: int = 2) -> list[dict]:
    """Recipes that worked for other CVEs of this repository, newest first."""
    d = recipe_dir(a, task)
    files = sorted(d.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True) if d.is_dir() else []
    out = []
    for f in files:
        try:
            r = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if all(r.get(k) for k in RECIPE_KEYS):
            out.append(r)
        if len(out) >= limit:
            break
    return out


def save_recipe(a: argparse.Namespace, bundle: Path, task: dict, recipe: dict) -> None:
    rec = {**{k: recipe[k] for k in RECIPE_KEYS}, "notes": recipe.get("notes"),
           "task_id": bundle.name, "cve": task.get("cve_id"),
           "vulnerable_commit": task.get("vulnerable_commit")}
    (bundle / "setup_recipe.json").write_text(json.dumps(rec, indent=2) + "\n")
    d = recipe_dir(a, task)
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{bundle.name}.json").write_text(json.dumps(rec, indent=2) + "\n")


def offline_check(image: str, build: str, test: str) -> tuple[bool, str]:
    """Build + existing tests as `agent`, no network, on a fresh copy of the source."""
    script = f"set -e; cp -r /opt/defensive/baseline /tmp/src && cd /tmp/src && ( {build} ) && ( {test} )"
    try:
        r = sh(["docker", "run", "--rm", "--network", "none", "--memory", MEM, *cpu_args(),
                "--pids-limit", "4096", image, "bash", "-c", script], timeout=3600)
    except subprocess.TimeoutExpired:
        return False, "offline build/test timed out"
    return r.returncode == 0, ((r.stdout or "") + (r.stderr or ""))[-600:]


def leak_check(bundle: Path, image: str, task: dict) -> tuple[str | None, dict]:
    """None if clean, else the failing status (LEAKED / FAILED)."""
    lk = sh(["docker", "run", "--rm", "--network", "none", "--user", "0",
             "-v", f"{(bundle / 'hidden').resolve()}:/opt/hidden:ro", image,
             "/opt/venv/bin/python", "-m", "cvepatch.core.taskgen.leakcheck",
             "--patch", "/opt/hidden/reference/fix.patch",
             "--baseline", "/opt/defensive/baseline",
             "--fix-commit", task.get("fixed_commit") or ""], timeout=3600)
    try:
        leak = json.loads(lk.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        leak = {"error": ((lk.stdout or "") + (lk.stderr or ""))[-300:]}
    if lk.returncode == 1:
        return "LEAKED", leak
    return (None if lk.returncode == 0 else "FAILED"), leak


def from_recipe(bundle: Path, base: str, final: str, recipe: dict, task: dict) -> dict:
    """Build the task image from a recipe, check it offline and for leaks."""
    with tempfile.TemporaryDirectory() as ctx:
        cdir = Path(ctx)
        (cdir / "install.sh").write_text(recipe["install_script"])
        (cdir / "setup.json").write_text(json.dumps(
            {k: recipe[k] for k in ("build_command", "test_command")}, indent=2))
        (cdir / "Dockerfile").write_text(RECIPE_DOCKERFILE.format(base=base, cmd=MCP_CMD))
        try:
            r = sh(["docker", "build", "-q", "--memory", MEM, *cpu_args(), "-t", final, str(cdir)],
                   timeout=3600)
        except subprocess.TimeoutExpired:
            return {"status": "RECIPE_FAILED", "reason": "install script timed out"}
    if r.returncode != 0:
        return {"status": "RECIPE_FAILED", "reason": "install script failed on a fresh base image",
                "log": ((r.stdout or "") + (r.stderr or ""))[-600:]}
    ok, log = offline_check(final, recipe["build_command"], recipe["test_command"])
    if not ok:
        sh(["docker", "rmi", "-f", final], timeout=300)
        return {"status": "RECIPE_FAILED", "reason": "build/test failed offline in the recipe image",
                "log": log}
    bad, leak = leak_check(bundle, final, task)
    if bad:
        sh(["docker", "rmi", "-f", final], timeout=300)
        return {"status": bad, "leak_check": leak,
                "reason": "upstream fix found in the setup image" if bad == "LEAKED"
                else "leak check did not run"}
    write_hidden(bundle, recipe["build_command"], recipe["test_command"], recipe)
    return {"status": "SETUP_OK", "image": final, "recipe": True, "leak_check": leak,
            **{k: recipe[k] for k in ("build_command", "test_command")}}


def build_base(bundle: Path, base: str) -> dict | None:
    stage_pkg(bundle)
    b = sh(["docker", "build", "-q", "--memory", MEM, *cpu_args(), "-t", base, str(bundle)],
           timeout=3600)
    if b.returncode != 0:
        return {"status": "FAILED", "reason": "base image build failed",
                "log": ((b.stdout or "") + (b.stderr or ""))[-600:]}
    return None


def rebuild(bundle: Path) -> dict:
    """Recreate a SETUP_OK task's image from its saved recipe (another pod, no LLM)."""
    task = json.loads((bundle / "hidden" / "task.json").read_text())
    recipe = json.loads((bundle / "setup_recipe.json").read_text())
    base, final = f"local/defensive-{bundle.name}:base", f"local/defensive-{bundle.name}:latest"
    return build_base(bundle, base) or from_recipe(bundle, base, final, recipe, task)


def setup_one(bundle: Path, a: argparse.Namespace) -> dict:
    task_id = bundle.name
    task = json.loads((bundle / "hidden" / "task.json").read_text())
    cve, meta = task["cve_id"], task["metadata"]
    base, raw = f"local/defensive-{task_id}:base", f"local/defensive-{task_id}:setup-raw"
    final = f"local/defensive-{task_id}:latest"
    rec: dict = {"task_id": task_id, "cve": cve}

    failed = build_base(bundle, base)
    if failed:
        return rec | failed

    # 1. Another CVE of this repo already has a working recipe: try it, no LLM.
    for recipe in repo_recipes(a, task):
        r = from_recipe(bundle, base, final, recipe, task)
        if r["status"] == "SETUP_OK":
            save_recipe(a, bundle, task, recipe)
            return rec | r | {"reused_from": recipe.get("task_id")}
        if r["status"] == "LEAKED":
            return rec | r
        rec.setdefault("reuse_failed", []).append(recipe.get("task_id"))

    # 2. Setup episode.
    run_dir = bundle / "setup_run"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir()
    name = f"cvepatch-setup-{task_id}-{uuid.uuid4().hex[:6]}"
    try:
        client, ep = asyncio.run(run_setup_episode(
            base, name, run_dir, model=a.model, cve=cve, turns=a.turns, timeout_s=a.timeout))
        rec |= {"model": a.model, "turns": ep.turns_used, "exit_reason": ep.exit_reason,
                "tokens_in": ep.tokens_in, "tokens_out": ep.tokens_out}
    except Exception as e:  # noqa: BLE001
        sh(["docker", "rm", "-f", name], timeout=120)
        leaf = root_cause(e)
        return rec | {"status": "FAILED",
                      "reason": f"setup episode crashed: {type(leaf).__name__}: {leaf}"[:300]}

    setup = last_setup(run_dir)
    checks: dict = {"setup_submitted": setup is not None}
    if setup is None:
        sh(["docker", "rm", "-f", name], timeout=120)
        if (rec.get("exit_reason") or "").startswith("error:"):
            # The model service failed (outage, proxy restart), not the agent: retryable.
            rec |= {"status": "FAILED", "reason": f"model call failed: {rec['exit_reason']}"}
        else:
            rec |= {"status": "SETUP_FAILED", "reason": "no accepted submit_setup"}
    else:
        # 3. Prefer an image built from the recipe (portable, reusable); fall back
        #    to the committed session container if the recipe does not reproduce.
        r = from_recipe(bundle, base, final, setup, task) if setup.get("install_script") \
            else {"status": "RECIPE_FAILED", "reason": "no install_script"}
        if r["status"] == "SETUP_OK":
            save_recipe(a, bundle, task, setup)
            rec |= r
        elif r["status"] == "LEAKED":
            rec |= r
        else:
            rec["recipe_failure"] = r.get("reason")
            c = sh(["docker", "commit", name, raw], timeout=1800)
            if c.returncode != 0:
                rec |= {"status": "FAILED", "reason": "docker commit failed", "log": c.stderr[-400:]}
            else:
                rec |= reset_and_check(bundle, base, raw, final, setup, task)
            sh(["docker", "rmi", raw], timeout=300)   # the tag only; final keeps the layers
        sh(["docker", "rm", "-f", name], timeout=120)
        checks["leak_free"] = rec["status"] == "SETUP_OK"
        checks["recipe"] = bool(rec.get("recipe"))

    if not a.no_langfuse:
        post_episode(getattr(client, "_run_trace_id", None),
                     {"tier": rec["status"].lower(), "cve_id": cve, "checks": checks,
                      "failure_reasons": [rec["reason"]] if rec.get("reason") else []},
                     run_dir, run_id=f"setup-{task_id}", env_id=f"defensive-{task_id}",
                     model=a.model, lang=meta.get("ecosystem"), phase="setup",
                     labels={**(meta.get("labels") or {}), "setup_model": a.model})
    return rec


def reset_and_check(bundle: Path, base: str, raw: str, final: str, setup: dict, task: dict) -> dict:
    with tempfile.TemporaryDirectory() as ctx:
        cdir = Path(ctx)
        (cdir / "setup.json").write_text(json.dumps(
            {k: setup[k] for k in ("build_command", "test_command")}, indent=2))
        (cdir / "Dockerfile").write_text(RESET_DOCKERFILE.format(base=base, raw=raw, cmd=MCP_CMD))
        r = sh(["docker", "build", "-q", "-t", final, str(cdir)], timeout=3600)
    if r.returncode != 0:
        return {"status": "FAILED", "reason": "reset build failed",
                "log": ((r.stdout or "") + (r.stderr or ""))[-600:]}
    bad, leak = leak_check(bundle, final, task)
    out = {"build_command": setup["build_command"], "test_command": setup["test_command"],
           "notes": setup.get("notes"), "leak_check": leak, "recipe": False}
    if bad:
        sh(["docker", "rmi", "-f", final], timeout=300)
        return out | {"status": bad, "reason": "upstream fix found in the setup image"
                      if bad == "LEAKED" else "leak check did not run"}
    write_hidden(bundle, setup["build_command"], setup["test_command"], setup)
    return out | {"status": "SETUP_OK", "image": final}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True, help="dir with task bundles")
    ap.add_argument("--model", default="openai/glm-5.3")
    ap.add_argument("--turns", type=int, default=80)
    ap.add_argument("--timeout", type=int, default=5400, help="seconds per setup episode")
    ap.add_argument("--retry", action="store_true", help="redo bundles whose setup did not succeed")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-langfuse", action="store_true")
    ap.add_argument("--recipes", type=Path, default=None,
                    help="per-repo recipe store (default: <out>/../setup-recipes)")
    a = ap.parse_args()
    a.recipes = a.recipes or a.out.parent / "setup-recipes"

    bundles = []
    for tj in sorted(a.out.glob("*/hidden/task.json")) + sorted(a.out.glob("*/*/hidden/task.json")):
        b = tj.parent.parent
        try:
            if json.loads(tj.read_text())["metadata"].get("setup_mode") != "agent":
                continue
        except (ValueError, KeyError):
            continue
        prev = b / "setup_result.json"
        if prev.is_file():
            st = json.loads(prev.read_text()).get("status")
            if st == "SETUP_OK" or not a.retry:
                continue
        bundles.append(b)
    if a.limit:
        bundles = bundles[: a.limit]

    stats = Counter()
    with (a.out / "setup.jsonl").open("a") as log:
        for i, b in enumerate(bundles, 1):
            try:
                rec = setup_one(b, a)
            except Exception as e:  # noqa: BLE001
                rec = {"task_id": b.name, "status": "FAILED", "reason": f"{type(e).__name__}: {e}"[:300]}
            if rec["status"] == "FAILED" and not docker_alive():
                print(f"[{i}/{len(bundles)}] {b.name}: docker daemon is gone; stopping",
                      file=sys.stderr, flush=True)
                return 1
            (b / "setup_result.json").write_text(json.dumps(rec, indent=2) + "\n")
            stats[rec["status"]] += 1
            log.write(json.dumps(rec) + "\n")
            log.flush()
            print(f"[{i}/{len(bundles)}] {b.name}: {rec['status']} - {rec.get('reason', '')[:90]}",
                  file=sys.stderr, flush=True)
    print(json.dumps({"bundles": len(bundles), "by_status": dict(stats)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
