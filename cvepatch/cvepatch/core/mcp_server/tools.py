"""Defensive MCP tool surface (runs inside the task container, as `agent`).

Mirrors the existing env conventions (see testenvs/defensive-fixture) so the
shared runner drives it without special cases. The tools let the agent
inspect a read-only source baseline, iterate a candidate patch in a writable
workspace, run the (public) approved tests, and finally submit a patch +
root-cause report.

Security posture:
  * read/list/search are confined to the source baseline + workspace; path
    traversal and symlink escapes are rejected.
  * `apply_patch` validates the unified diff (format + paths) before touching
    the workspace.
  * `run_command` gives the agent a shell in its own container (no network),
    so NOTHING hidden may be in the episode image: the upstream fix, the
    upstream tests and the full task manifest live in the bundle's `hidden/`
    dir, which is bind-mounted into the verifier's container only.
    `setup()` returns a SAFE subset of the (already redacted) task manifest.
  * The trusted grader (`grade_defensive`) is NOT defined here — it runs
    post-episode in a fresh container. Declaring it as an `evaluation_tool`
    in the env manifest keeps the loop from ever exposing it.

The logic lives in `DefensiveToolbox` (plain Python, unit-testable without
Docker/MCP); the module-level `mcp` object wires each method to FastMCP when
run as `__main__` inside the container.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from cvepatch.core import DEFENSIVE_INTERFACE
from cvepatch.core import manifest as task_manifest
from cvepatch.core.validation import v4a_patch
from cvepatch.core.validation.patch_validator import (
    PatchValidationError,
    apply_patch_to_tree,
    diff_paths,
    split_diff,
    validate_patch,
)

MAX_READ_BYTES = 256 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
EXEC_TIMEOUT_SECONDS = 120
RUN_COMMAND_DEFAULT_S = 600
RUN_COMMAND_MAX_S = 1800
SETUP_CHECK_TIMEOUT_S = 1800
# Written into the image by scripts/agent_setup.py after a setup episode: the
# build and test commands the agent found (they say nothing about the fix).
SETUP_ENV_PATH = Path("/opt/defensive/task/setup.json")

SETUP_INSTRUCTIONS = (
    "This is a SETUP task, not the fix. The source at {src} (read-only; your writable "
    "copy is {cand}) has a published vulnerability (see `advisory`); a later, separate "
    "session will fix it offline in the environment you prepare now.\n"
    "Your job: make the project build and make its existing test suite run.\n"
    "- You are root and the network is ON: install system packages (apt-get), language "
    "toolchains and dependencies as needed.\n"
    "- Fetch EVERYTHING now. The build and test commands must later work with NO network, "
    "as the unprivileged user 'agent' (HOME=/home/agent), from a clean copy of the source.\n"
    "- Do NOT download this project's own source again or any newer version of it (no git "
    "clone/fetch/pull of its repository, no installing its released package). The image is "
    "scanned for the upstream fix and rejected if it is found.\n"
    "- Do not change the project's source to make things work; configure, install and pick "
    "commands instead. Your workspace is wiped after setup.\n"
    "- Do NOT try to reproduce, exploit or fix the vulnerability: that is the next "
    "session's job. Stop as soon as the build and tests work.\n"
    "- Pick a test command that runs the project's own tests and PASSES on this code. If a "
    "few tests fail for environmental reasons, run a passing subset that still covers the "
    "code named in the advisory.\n"
    "- Also write install_script: the full text of ONE bash script (pass it as the "
    "install_script argument; do not save it into the source tree) that, run as root with network on a FRESH "
    "copy of this same base image (working directory: a fresh copy of the source), installs "
    "everything you installed (apt-get, pip, gem, language toolchains, downloaded "
    "dependencies). It must not build the project. The saved environment is built from this "
    "script, not from your session, so anything missing from it is lost.\n"
    "When everything works, call submit_setup(build_command, test_command, install_script, "
    "notes). It re-runs install_script as root (it must succeed again), then build and test as "
    "'agent' on a fresh copy of the source, and tells you if anything fails; fix and call it "
    "again. The test command runs after the build command in the same tree."
)

# Fields of the task manifest that are SAFE to show the agent. Deliberately
# excludes fixed_commit / patch_commit / patch_provenance / reference patch —
# revealing those would hand the agent the answer.
_SAFE_TASK_FIELDS = (
    "task_id", "cve_id", "product", "component", "vulnerability_class", "cwe_ids",
    "affected_versions", "vulnerable_commit", "source_repository", "network_policy",
)


def _truncate(s: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    b = s.encode("utf-8", errors="replace")
    if len(b) <= limit:
        return s
    return b[: limit - 32].decode("utf-8", errors="replace") + "\n<truncated>"


class DefensiveToolbox:
    """Implements the defensive tools against on-disk source + workspace."""

    def __init__(
        self,
        *,
        source_dir: Path,
        workspace_dir: Path,
        task_path: Path,
        allowed_test_commands: dict[str, list[str]] | None = None,
        allowed_static_tools: dict[str, list[str]] | None = None,
        mode: str = "episode",
    ) -> None:
        self.mode = mode
        self.source_dir = Path(source_dir).resolve()
        self.workspace_dir = Path(workspace_dir).resolve()
        self.task_path = Path(task_path)
        self.task = task_manifest.load(self.task_path)
        # The tree the agent patches: a writable copy (copy mode) or, in git
        # mode, the source tree itself (too large to copy; the grader works on
        # its own pristine tree in a fresh container, so edits here can't
        # affect grading).
        self.git_mode = self.task.checkout_mode == "git"
        self.candidate_dir = self.source_dir if self.git_mode else self.workspace_dir / "src"
        # Allowlisted test selectors -> argv (run inside candidate_dir).
        self.allowed_test_commands = allowed_test_commands or {}
        self.allowed_static_tools = allowed_static_tools or {}
        self._ensure_workspace()

    # --------------------------------------------------------------- helpers
    def _ensure_workspace(self) -> None:
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        if self.git_mode:
            return
        if not self.candidate_dir.exists():
            shutil.copytree(self.source_dir, self.candidate_dir, symlinks=False)
            # The source baseline is mounted read-only in the task image
            # (`chmod -R a-w /rlenv/src`), and copytree preserves those mode
            # bits — leaving the candidate workspace unwritable, so apply_patch
            # and builds fail with EACCES. Restore owner write/exec across the
            # candidate tree so the agent can actually iterate a fix.
            self._make_writable(self.candidate_dir)

    @staticmethod
    def _make_writable(root: Path) -> None:
        import os
        import stat
        for dirpath, dirnames, filenames in os.walk(root):
            for name in (*dirnames, *filenames):
                p = os.path.join(dirpath, name)
                try:
                    mode = os.stat(p).st_mode
                    # dirs need +wx to create/enter; files need +w.
                    add = stat.S_IWUSR | (stat.S_IXUSR if os.path.isdir(p) else 0)
                    os.chmod(p, mode | add)
                except OSError:
                    continue
        with contextlib.suppress(OSError):
            os.chmod(root, os.stat(root).st_mode | stat.S_IWUSR | stat.S_IXUSR)

    def _resolve_readable(self, path: str) -> Path | None:
        """Resolve `path` and confirm it is inside source_dir or workspace."""
        p = Path(path)
        if not p.is_absolute():
            # Relative paths are interpreted against the source baseline.
            p = self.source_dir / p
        try:
            rp = p.resolve()
        except (OSError, RuntimeError):
            return None
        for root in (self.source_dir, self.workspace_dir):
            try:
                rp.relative_to(root)
                return rp
            except ValueError:
                continue
        return None

    # ---------------------------------------------------------------- setup
    def setup(self) -> dict[str, Any]:
        safe = {k: self.task.raw.get(k) for k in _SAFE_TASK_FIELDS if k in self.task.raw}
        meta = self.task.raw.get("metadata") or {}
        if self.mode == "setup":
            return {
                "task": safe, "advisory": meta.get("advisory"), "language": meta.get("ecosystem"),
                "instructions": SETUP_INSTRUCTIONS.format(src=self.source_dir,
                                                          cand=self.candidate_dir),
                "submission_format": {"submit_setup": {
                    "build_command": "<shell command, run from the repo root>",
                    "test_command": "<shell command, run from the repo root after the build>",
                    "notes": "<what you installed and why>"}},
            }
        env = self._setup_env()
        return {
            "task": safe,
            "advisory": meta.get("advisory"),
            "language": meta.get("ecosystem"),
            "instructions": (
                "A published vulnerability (see `advisory`) exists in the source at "
                f"{self.source_dir} (read-only; your writable copy is {self.candidate_dir}). "
                "Work like a maintainer fixing it:\n"
                "1. LOCATE: read the advisory and the code; find the root cause.\n"
                "2. REPRODUCE: write a regression test, in the project's own test "
                "framework, that FAILS on the current vulnerable code because of this "
                "bug. Run it with run_command() and confirm it fails for the right reason.\n"
                "3. PATCH: write a minimal fix in the source (not in the test).\n"
                "4. VERIFY: your test now passes and the project's existing tests still pass.\n"
                "5. SUBMIT: call submit_fix(test_files, test_command) with the paths of "
                "the test files you added/changed and the exact command that runs your "
                "test; then submit_report() with the root cause.\n"
                "No network. Dependencies are already installed. An independent verifier "
                "re-runs your test against the vulnerable code, your fix and reference "
                "fixes in a fresh container."
            ),
            "constraints": {
                "network": self.task.network_policy,
                "writable_paths": [str(self.candidate_dir)],
                "patched_files_allowlist": list(self.task.patched_files_allowlist),
                "run_command_timeout_s": {"default": RUN_COMMAND_DEFAULT_S,
                                          "max": RUN_COMMAND_MAX_S},
            },
            "submission_format": {
                "submit_fix": {"test_files": ["<repo-relative test file paths>"],
                               "test_command": "<shell command run from the repo root>"},
                "submit_report": {"report": "<root_cause_report v1 object>"},
            },
            "task_profile": {
                "env_id": self.task.task_id,
                "task_type": "binary_patch",
                "interface": DEFENSIVE_INTERFACE,
                "episode_tools": [
                    "setup", "read_file", "list_directory", "search_code", "inspect_diff",
                    "run_command", "write_file", "apply_patch", "submit_fix", "submit_report",
                    *(["run_tests", "run_static_analysis", "submit_patch"]
                      if os.environ.get("DEF_LEGACY_TOOLS") == "1" else []),
                ],
                "capability_flags_emitted": [],  # verified post-episode, not here
            },
            **({"available_tests": sorted(self.allowed_test_commands),
                "available_static_tools": sorted(self.allowed_static_tools)}
               if os.environ.get("DEF_LEGACY_TOOLS") == "1" else {}),
            **({"environment": {**env, "note": "how this project is built and tested here "
                                "(found during environment setup); your test command may "
                                "reuse them"}} if env else {}),
        }

    @staticmethod
    def _setup_env() -> dict[str, str]:
        try:
            d = json.loads(SETUP_ENV_PATH.read_text())
        except (OSError, ValueError):
            return {}
        return {k: d[k] for k in ("build_command", "test_command") if d.get(k)}

    def submit_setup(self, build_command: str, test_command: str, install_script: str = "",
                     notes: str = "") -> dict[str, Any]:
        """Setup mode: re-run install_script as root (it must be repeatable), then build +
        test as `agent`, each on a fresh copy of the source."""
        if self.mode != "setup":
            return {"ok": False, "error": "submit_setup is only available in a setup session"}
        if not (build_command or "").strip() or not (test_command or "").strip():
            return {"ok": False, "error": "build_command and test_command are both required"}
        if not (install_script or "").strip():
            return {"ok": False, "error": "install_script is required: the bash script that "
                    "installs everything this project needs on a fresh base image"}
        check = Path(tempfile.mkdtemp(prefix="setup-check-"))
        tree = check / "src"
        try:
            shutil.copytree(self.source_dir, tree, symlinks=True)
            self._make_writable(tree)
            as_root = os.geteuid() == 0
            timings = {}
            script = check / "install.sh"
            script.write_text(install_script)
            syn = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
            if syn.returncode != 0:
                return {"ok": False, "step": "install", "error": "install_script has a bash "
                        "syntax error", "stderr": _truncate(syn.stderr, 4096)}
            inst = check / "inst-src"
            shutil.copytree(self.source_dir, inst, symlinks=True)
            self._make_writable(inst)
            t0 = time.monotonic()
            try:
                proc = subprocess.run(["bash", "-e", str(script)], cwd=str(inst),
                                      capture_output=True, text=True, timeout=SETUP_CHECK_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                return {"ok": False, "step": "install",
                        "error": f"install_script timed out after {SETUP_CHECK_TIMEOUT_S}s"}
            timings["install_s"] = round(time.monotonic() - t0)
            if proc.returncode != 0:
                return {"ok": False, "step": "install", "exitcode": proc.returncode,
                        "error": "install_script failed when re-run as root (it must succeed "
                                 "on a fresh base image, so it must also be repeatable)",
                        "stdout": _truncate(proc.stdout, 16 * 1024),
                        "stderr": _truncate(proc.stderr, 16 * 1024)}
            if as_root:
                subprocess.run(["chown", "-R", "agent", str(check)], check=False)
            for step, cmd in (("build", build_command), ("test", test_command)):
                argv = (["runuser", "-u", "agent", "--"] if as_root else []) + ["bash", "-c", cmd]
                env = {**os.environ, "HOME": "/home/agent", "USER": "agent"} if as_root else None
                t0 = time.monotonic()
                try:
                    proc = subprocess.run(argv, cwd=str(tree), capture_output=True, text=True,
                                          timeout=SETUP_CHECK_TIMEOUT_S, env=env)
                except subprocess.TimeoutExpired:
                    return {"ok": False, "step": step,
                            "error": f"{step} command timed out after {SETUP_CHECK_TIMEOUT_S}s"}
                timings[f"{step}_s"] = round(time.monotonic() - t0)
                if proc.returncode != 0:
                    return {"ok": False, "step": step, "exitcode": proc.returncode,
                            "error": f"{step} command failed when re-run as user 'agent' on a "
                                     "fresh copy of the source",
                            "stdout": _truncate(proc.stdout, 16 * 1024),
                            "stderr": _truncate(proc.stderr, 16 * 1024)}
        finally:
            shutil.rmtree(check, ignore_errors=True)
        return {"ok": True, "accepted": True, "build_command": build_command,
                "test_command": test_command, "install_script": install_script,
                "notes": notes, **timings,
                "note": "setup recorded; the environment is saved and checked after this session."}

    # ------------------------------------------------------------------- fs
    def read_file(self, path: str) -> dict[str, Any]:
        rp = self._resolve_readable(path)
        if rp is None:
            return {"error": f"path not allowed or escapes sandbox: {path!r}"}
        if not rp.is_file():
            return {"error": f"not a file: {path}"}
        data = rp.read_bytes()[:MAX_READ_BYTES]
        return {"path": str(rp), "contents": data.decode("utf-8", errors="replace")}

    def list_directory(self, path: str) -> dict[str, Any]:
        rp = self._resolve_readable(path)
        if rp is None:
            return {"error": f"path not allowed or escapes sandbox: {path!r}"}
        if not rp.is_dir():
            return {"error": f"not a directory: {path}"}
        entries = []
        for child in sorted(rp.iterdir()):
            try:
                st = child.stat()
                entries.append({"name": child.name,
                                "type": "dir" if child.is_dir() else "file",
                                "size": st.st_size})
            except OSError:
                continue
        return {"path": str(rp), "entries": entries}

    def search_code(self, query: str, path: str = ".") -> dict[str, Any]:
        rp = self._resolve_readable(path) or self.source_dir
        if not query:
            return {"error": "empty query"}
        grep = shutil.which("grep")
        if not grep:
            # Pure-python fallback.
            hits = []
            base = rp if rp.is_dir() else rp.parent
            for f in base.rglob("*"):
                if not f.is_file():
                    continue
                try:
                    for i, line in enumerate(f.read_text("utf-8", errors="replace").splitlines(), 1):
                        if query in line:
                            hits.append(f"{f}:{i}:{line}")
                            if len(hits) >= 200:
                                break
                except OSError:
                    continue
            return {"matches": _truncate("\n".join(hits))}
        proc = subprocess.run(
            [grep, "-rnI", "--", query, str(rp)],
            capture_output=True, text=True, timeout=30,
        )
        return {"matches": _truncate(proc.stdout)}

    def inspect_diff(self, base: str = "source", candidate: str = "workspace") -> dict[str, Any]:
        """Show the unified diff of the candidate workspace vs the pristine source."""
        if self.git_mode:
            d = self._derive_diff()
            return {"diff": _truncate(d), "has_changes": bool(d.strip())}
        diff = shutil.which("diff")
        if not diff:
            return {"error": "diff tool unavailable"}
        proc = subprocess.run(
            [diff, "-ruN", str(self.source_dir), str(self.candidate_dir)],
            capture_output=True, text=True, timeout=30,
        )
        return {"diff": _truncate(proc.stdout), "has_changes": bool(proc.stdout.strip())}

    # --------------------------------------------------------------- patch
    def _writable(self, path: str) -> Path | None:
        """`path` inside the candidate tree (absolute or project-relative), else None.
        A path into the read-only source tree means the same file in the copy."""
        p = Path(path)
        if p.is_absolute() and not self.git_mode:
            with contextlib.suppress(ValueError):
                p = self.candidate_dir / p.relative_to(self.source_dir)
        target = p if p.is_absolute() else self.candidate_dir / p
        try:
            rp = target.resolve()
            rp.relative_to(self.candidate_dir)
        except (OSError, RuntimeError, ValueError):
            return None
        return rp

    def apply_patch(self, patch: str) -> dict[str, Any]:
        if v4a_patch.is_v4a(patch or ""):
            # '*** Begin Patch' (Codex / gpt-oss format).
            allow = tuple(self.task.patched_files_allowlist)

            def resolve(path: str) -> Path | None:
                rp = self._writable(path)
                if rp is None or (allow and str(rp.relative_to(self.candidate_dir)) not in allow):
                    return None
                return rp
            try:
                touched = v4a_patch.apply(patch, self.candidate_dir, resolve)
            except v4a_patch.V4AError as exc:
                return {"ok": False, "error": f"patch rejected: {exc}"}
            return {"ok": True, "format": "v4a", "paths": touched}
        try:
            info = validate_patch(
                patch, allowlist=self.task.patched_files_allowlist, require_nonempty=True
            )
        except PatchValidationError as exc:
            return {"ok": False, "error": f"patch rejected: {exc}"}
        if info.disallowed:
            return {"ok": False,
                    "error": f"patch touches files outside the allowlist: {list(info.disallowed)}"}
        res = apply_patch_to_tree(info, self.candidate_dir)
        return {"ok": res.ok, "tool": res.tool, "detail": res.detail,
                "paths": list(info.paths), "sha256": info.sha256}

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        """Create/overwrite a file inside the writable candidate tree."""
        rp = self._writable(path)
        if rp is None:
            return {"ok": False, "error": f"path not writable (outside {self.candidate_dir}): {path!r}"}
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(content, encoding="utf-8")
        return {"ok": True, "path": str(rp), "bytes": len(content.encode("utf-8"))}

    def run_command(self, command: str, timeout_s: int = RUN_COMMAND_DEFAULT_S) -> dict[str, Any]:
        """Run a shell command in the candidate tree (no network, agent user)."""
        if not command.strip():
            return {"error": "empty command"}
        t = max(1, min(int(timeout_s or RUN_COMMAND_DEFAULT_S), RUN_COMMAND_MAX_S))
        try:
            proc = subprocess.run(["bash", "-c", command], cwd=str(self.candidate_dir),
                                  capture_output=True, text=True, timeout=t)
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return {"exitcode": None, "timed_out": True, "timeout_s": t,
                    "stdout": _truncate(out, 32 * 1024)}
        return {"exitcode": proc.returncode, "stdout": _truncate(proc.stdout),
                "stderr": _truncate(proc.stderr)}

    # ------------------------------------------------------------- analysis
    def run_static_analysis(self, tool: str, args: str = "") -> dict[str, Any]:
        argv = self.allowed_static_tools.get(tool)
        if argv is None:
            return {"error": f"static-analysis tool not allowlisted: {tool!r}; "
                             f"available: {sorted(self.allowed_static_tools)}"}
        extra = args.split() if args else []
        proc = subprocess.run(
            [*argv, *extra], cwd=str(self.candidate_dir),
            capture_output=True, text=True, timeout=EXEC_TIMEOUT_SECONDS,
        )
        return {"exitcode": proc.returncode,
                "stdout": _truncate(proc.stdout), "stderr": _truncate(proc.stderr)}

    def run_tests(self, test_selector: str = "all") -> dict[str, Any]:
        """Run an allowlisted test selector inside the candidate workspace.

        Only approved selectors run. The hidden grader is never here; the
        regression/functional tests are part of the (public) source baseline,
        so letting the defender run them is expected, not a leak.
        """
        selectors = (
            list(self.allowed_test_commands)
            if test_selector in ("all", "", None)
            else [test_selector]
        )
        out: dict[str, Any] = {}
        for sel in selectors:
            argv = self.allowed_test_commands.get(sel)
            if argv is None:
                out[sel] = {"error": f"test selector not allowlisted: {sel!r}"}
                continue
            proc = subprocess.run(
                argv, cwd=str(self.candidate_dir),
                capture_output=True, text=True, timeout=EXEC_TIMEOUT_SECONDS,
            )
            out[sel] = {"exitcode": proc.returncode,
                        "stdout": _truncate(proc.stdout), "stderr": _truncate(proc.stderr)}
        return {"results": out}

    # ------------------------------------------------------------- submit
    def _derive_diff(self) -> str:
        if self.git_mode:
            # Tracked edits + new (untracked, non-ignored) files, as a/ b/ diff.
            subprocess.run(["git", "-C", str(self.source_dir), "add", "-N", "--", "."],
                           capture_output=True, timeout=60)
            proc = subprocess.run(["git", "-C", str(self.source_dir), "diff", "--no-color"],
                                  capture_output=True, text=True, timeout=120)
            return proc.stdout
        diff = shutil.which("diff")
        if not diff:
            return ""
        proc = subprocess.run(
            [diff, "-ruN", str(self.source_dir), str(self.candidate_dir)],
            capture_output=True, text=True, timeout=30,
        )
        # Rewrite the absolute a/b prefixes to repo-relative a/<rel> b/<rel>.
        return _rewrite_diff_prefixes(proc.stdout, self.source_dir, self.candidate_dir)

    def submit_patch(
        self, patch: str | None = None, patch_path: str | None = None,
        base_revision: str | None = None,
    ) -> dict[str, Any]:
        """Finalize the candidate patch.

        Precedence: explicit `patch` text > `patch_path` (file in workspace) >
        the diff derived from the edited workspace. The FULL patch text is
        echoed in the result so it lands in the host-written transcript the
        trusted grader reads (the agent's container is gone by grading time).
        """
        text = patch
        if text is None and patch_path:
            rp = self._resolve_readable(patch_path)
            if rp is None or not rp.is_file():
                return {"ok": False, "error": f"patch_path not readable: {patch_path!r}"}
            text = rp.read_text("utf-8", errors="replace")
        if text is None:
            text = self._derive_diff()
        if not text.strip():
            return {"ok": False, "error": "no patch to submit (empty diff)"}
        try:
            info = validate_patch(
                text, allowlist=self.task.patched_files_allowlist, require_nonempty=True
            )
        except PatchValidationError as exc:
            return {"ok": False, "error": f"patch rejected: {exc}", "patch": text}
        return {
            "ok": True,
            "accepted": True,
            "patch": text,                 # echoed for the transcript -> grader
            "base_revision": base_revision,
            "sha256": info.sha256,
            "paths": list(info.paths),
            "note": "submission recorded; final verdict is produced by the "
                    "independent post-episode grader.",
        }

    def submit_fix(self, test_files: list[str], test_command: str) -> dict[str, Any]:
        """Finalize: split the workspace diff into the regression test and the fix.

        Both diffs and the command are echoed in the result so they ride the
        host-written transcript to the post-episode verifier.
        """
        if isinstance(test_files, str):
            test_files = [t for t in test_files.replace(",", " ").split() if t]
        test_files = [str(t).strip().lstrip("./") for t in (test_files or []) if str(t).strip()]
        if not test_files:
            return {"ok": False, "error": "test_files is empty: list the test files you added/changed"}
        if not (test_command or "").strip():
            return {"ok": False, "error": "test_command is empty"}
        full = self._derive_diff()
        if not full.strip():
            return {"ok": False, "error": "no changes in the workspace"}
        test_patch, fix_patch = split_diff(full, test_files)
        changed = diff_paths(full)
        missing = [t for t in test_files if t not in changed]
        if missing:
            return {"ok": False, "error": f"test_files not changed in the workspace: {missing}",
                    "changed_files": changed}
        if not fix_patch.strip():
            return {"ok": False, "error": "no source change outside the test files (no fix)",
                    "changed_files": changed}
        for name, text in (("test", test_patch), ("fix", fix_patch)):
            try:
                validate_patch(text, require_nonempty=True)
            except PatchValidationError as exc:
                return {"ok": False, "error": f"{name} diff rejected: {exc}"}
        return {
            "ok": True,
            "accepted": True,
            "test_files": test_files,
            "test_command": test_command,
            "test_patch": test_patch,
            "fix_patch": fix_patch,
            "fix_files": [p for p in changed if p not in test_files],
            "note": "submission recorded; the independent verifier runs after the episode.",
        }

    def submit_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Record the root-cause report. Echoed into the result (-> transcript)."""
        if not isinstance(report, dict):
            return {"ok": False, "error": "report must be an object"}
        return {"ok": True, "report": report,
                "note": "report recorded; evaluated mechanically + separately "
                        "from the patch verdict."}


def _rewrite_diff_prefixes(diff_text: str, source_dir: Path, cand_dir: Path) -> str:
    """Normalize `diff -ruN <abs_a> <abs_b>` output to a/<rel> b/<rel> form."""
    src = str(source_dir)
    cand = str(cand_dir)
    out_lines: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("--- "):
            rest = line[4:]
            path = rest.split("\t", 1)[0]
            rel = _rel(path, src, cand)
            out_lines.append(f"--- a/{rel}" if rel else line)
        elif line.startswith("+++ "):
            rest = line[4:]
            path = rest.split("\t", 1)[0]
            rel = _rel(path, src, cand)
            out_lines.append(f"+++ b/{rel}" if rel else line)
        elif line.startswith("diff "):
            continue  # drop the `diff -ruN <abs> <abs>` command header
        else:
            out_lines.append(line)
    return "\n".join(out_lines) + ("\n" if diff_text.endswith("\n") else "")


def _rel(path: str, src: str, cand: str) -> str | None:
    for root in (src, cand):
        if path == root:
            return ""
        if path.startswith(root + os.sep):
            return path[len(root) + 1:]
    return None


# ---------------------------------------------------------------------------
# FastMCP wiring (only when run inside the container)
# ---------------------------------------------------------------------------


def build_toolbox_from_env() -> DefensiveToolbox:
    """Construct a DefensiveToolbox from container env vars."""
    allowed_tests_raw = os.environ.get("DEF_ALLOWED_TESTS")
    allowed_tests = json.loads(allowed_tests_raw) if allowed_tests_raw else {
        "regression": ["./build/regression_test"],
        "functional": ["./build/functional_test"],
        "build": ["bash", "build.sh"],
    }
    allowed_static_raw = os.environ.get("DEF_ALLOWED_STATIC")
    allowed_static = json.loads(allowed_static_raw) if allowed_static_raw else {}
    return DefensiveToolbox(
        source_dir=Path(os.environ.get("DEF_SOURCE_DIR", "/rlenv/src")),
        workspace_dir=Path(os.environ.get("DEF_WORKSPACE_DIR", "/rlenv/workspace")),
        task_path=Path(os.environ.get("DEF_TASK_PATH", "/opt/defensive/task/defensive_task.json")),
        allowed_test_commands=allowed_tests,
        allowed_static_tools=allowed_static,
        mode=os.environ.get("DEF_MODE", "episode"),
    )


def register_tools(mcp: Any, box: DefensiveToolbox) -> None:
    """Register the toolbox's methods as MCP tools.

    Each tool is a function with an EXPLICIT, typed signature so FastMCP
    generates a correct per-parameter input schema. (A previous `**kwargs`
    wrapper made FastMCP advertise a bogus `kwargs` object for every tool, so
    agents could not call anything — every call failed validation.)

    Results are JSON-stringified so the host transcript captures the structured
    content as text, which the trusted grader later parses back out of
    tool_calls.jsonl. `grade_defensive` is intentionally NOT registered.
    """

    setup_mode = box.mode == "setup"
    # The legacy benchmark tools (allowlisted run_tests / run_static_analysis,
    # diff-only submit_patch) do not apply to cvepatch tasks: offering them only
    # costs turns and clutters the traces. Old fixture envs set DEF_LEGACY_TOOLS=1.
    legacy = os.environ.get("DEF_LEGACY_TOOLS") == "1"

    def reg(name: str, description: str):
        """Register `fn` under `name` with a clean description (MCP uses the docstring)."""
        def deco(fn):
            fn.__doc__ = description
            return mcp.tool(name=name)(fn)
        return deco

    @reg("setup", "Start here. Returns the task: the vulnerability advisory (CVE id, CWE, "
          "description), where the vulnerable source is (read-only) and your writable copy, how "
          "the project is built and tested in this environment when known, the rules, and how "
          "to submit.")
    def setup() -> str:
        return json.dumps(box.setup())

    @reg("read_file", "Read a file from the read-only source tree or from your writable copy. "
          "Relative paths are resolved against the source tree; prefix the writable copy's "
          "path to read your edits. Returns up to 256 KB; for part of a large file use "
          "run_command with sed -n, head, tail or grep.")
    def read_file(path: str) -> str:
        return json.dumps(box.read_file(path))

    @reg("list_directory", "List a directory of the source tree or of your writable copy: "
          "each entry's name, type (file/dir) and size. Relative paths are resolved against "
          "the source tree.")
    def list_directory(path: str) -> str:
        return json.dumps(box.list_directory(path))

    @reg("search_code", "Search files for a pattern (grep -rnI: a basic regular expression, "
          "binary files skipped) and return the matching file:line:text lines. `path` limits "
          "the search to a sub-directory (default: the whole source tree).")
    def search_code(query: str, path: str = ".") -> str:
        return json.dumps(box.search_code(query, path))

    @reg("inspect_diff", "Show the unified diff between the pristine vulnerable source and "
          "your writable copy, i.e. everything you have changed so far.")
    def inspect_diff(base: str = "source", candidate: str = "workspace") -> str:
        return json.dumps(box.inspect_diff(base, candidate))

    @reg("apply_patch", "Edit files in your writable copy. Accepts either a unified diff "
          "(git diff / diff -u, paths relative to the project root) or the '*** Begin Patch' "
          "format (*** Add File / *** Update File / *** Delete File sections, *** End Patch). "
          "All changes apply or none do. For a whole new file, write_file is simplest.")
    def apply_patch(patch: str) -> str:
        return json.dumps(box.apply_patch(patch))

    @reg("write_file", "Create or overwrite a file in your writable copy with the given full "
          "content. The path is relative to the project root.")
    def write_file(path: str, content: str) -> str:
        return json.dumps(box.write_file(path, content))

    @reg("run_command",
          ("Run a bash command as root with network access, in your writable copy of the "
           "source (the project root). Use it to install packages and to build and test the "
           "project. " if setup_mode else
           "Run a bash command in your writable copy of the source (the project root). Use it "
           "to build the project, run tests and inspect code. There is no network; the "
           "project's dependencies are already installed. ")
          + f"Returns the exit code, stdout and stderr. timeout_s defaults to "
            f"{RUN_COMMAND_DEFAULT_S} and is capped at {RUN_COMMAND_MAX_S}.")
    def run_command(command: str, timeout_s: int = RUN_COMMAND_DEFAULT_S) -> str:
        return json.dumps(box.run_command(command, timeout_s))

    if not setup_mode:
        @reg("submit_fix", "Submit your work. test_files: the regression test files you "
              "added or changed; test_command: the shell command, run from the project root, "
              "that runs your test. Every other change in your writable copy is taken as the "
              "fix. An independent verifier then re-runs your test on the vulnerable code (it "
              "must fail), on your fixed code (it must pass), and runs the existing tests.")
        def submit_fix(test_files: list[str], test_command: str) -> str:
            return json.dumps(box.submit_fix(test_files, test_command))

        @reg("submit_report", "Record your root-cause analysis as an object, for example "
              "{root_cause, affected_code, trigger, impact, fix_summary}. Call it after "
              "submit_fix.")
        def submit_report(report: dict) -> str:
            return json.dumps(box.submit_report(report))

    if setup_mode:   # never on a patch episode's tool surface
        @reg("submit_setup", "Record how this project is set up. install_script: the full "
              "TEXT of a bash script (not a file path) that, run as root with network on a fresh copy of this base image "
              "(working directory: a fresh copy of the source), installs every dependency; it "
              "must not build the project. build_command / test_command: build the project and "
              "run its existing tests from the project root, offline, as user 'agent'. All "
              "three are re-run on a fresh copy of the source before the setup is accepted.")
        def submit_setup(build_command: str, test_command: str, install_script: str,
                         notes: str = "") -> str:
            return json.dumps(box.submit_setup(build_command, test_command, install_script, notes))

    if legacy:
        @reg("run_static_analysis", "Run an allowlisted static-analysis tool.")
        def run_static_analysis(tool: str, args: str = "") -> str:
            return json.dumps(box.run_static_analysis(tool, args))

        @reg("run_tests", "Run approved tests ('build' | 'regression' | 'functional' | 'all').")
        def run_tests(test_selector: str = "all") -> str:
            return json.dumps(box.run_tests(test_selector))

        @reg("submit_patch", "Submit the final unified diff for independent grading.")
        def submit_patch(patch: str = "", patch_path: str = "", base_revision: str = "") -> str:
            return json.dumps(box.submit_patch(patch or None, patch_path or None,
                                               base_revision or None))


def main() -> None:  # pragma: no cover - container entrypoint
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("defensive-vuln")
    register_tools(mcp, build_toolbox_from_env())
    mcp.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
