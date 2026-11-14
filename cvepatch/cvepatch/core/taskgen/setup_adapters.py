"""Adapters for projects with no hand-written builder: the agent sets them up.

The bundle starts from a toolchain base image with the vulnerable source and
no build or test commands. scripts/agent_setup.py then runs a setup episode
(network on, root) in which the agent gets the project building and its tests
running and reports the commands with submit_setup(). The container is
committed, reset to the vulnerable tree, leak-checked against the upstream
fix, and those commands are written into hidden/task.json and
hidden/oracle/setup_cmd.sh. Until then the bundle is not runnable.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from cvepatch.core.taskgen.core import Adapter, Plan

# Filled in by scripts/agent_setup.py: "( <build> ) && ( <test> )".
SETUP_ORACLE = 'bash "${ORACLE_DIR:-/opt/hidden/oracle}/setup_cmd.sh"'

TEST_DIRS = {"test", "tests", "testing", "testsuite", "t", "spec", "specs", "__tests__",
             "unittest", "unittests", "unit_tests", "regress", "regression", "fuzz"}
# test_x.c, x_test.c, x-tests.c, x.test.js, x.spec.ts, test.c (not latest.c);
# CamelCase FooTest.cs / FooTests.cs; Perl's *.t.
TEST_WORD_RE = re.compile(r"(^|[_\-.])(tests?|spec)([_\-.]|$)")
TEST_CAMEL_RE = re.compile(r"[a-z0-9]Tests?\.[A-Za-z]+$")
SOURCE_EXT = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".inl", ".ipp",
    ".m", ".mm", ".s", ".asm", ".y", ".l", ".def",
    ".rs", ".go", ".py", ".js", ".mjs", ".cjs", ".ts", ".java", ".kt", ".scala",
    ".cs", ".fs", ".vb", ".ex", ".exs", ".erl", ".hrl", ".php", ".rb", ".swift",
    ".lua", ".pl", ".pm", ".tcl", ".sh", ".zig", ".d", ".nim", ".ml", ".hs",
}
# Generic compile / link failure markers (gcc, clang, ld, dotnet, mix).
COMPILE_FAIL_RE = (r": (fatal )?error: |undefined reference to|ld returned 1 exit status"
                   r"|error CS\d{4}|== Compilation error|\(CompileError\)")


class AgentSetupAdapter(Adapter):
    """One instance per track; differs only in base image and dependency files."""

    def __init__(self, name: str, track: str, image: str, *, extra_apt: tuple[str, ...] = (),
                 dep_files: tuple[str, ...] = (), dep_suffixes: tuple[str, ...] = ()) -> None:
        self.name, self.track, self.image = name, track, image
        self.extra_apt = list(extra_apt)
        self.dep_files = dep_files
        self.dep_suffixes = dep_suffixes

    def is_dep_file(self, p):
        return super().is_dep_file(p) or (bool(self.dep_suffixes) and p.endswith(self.dep_suffixes))

    def is_test(self, p):
        pp = PurePosixPath(p)
        return (bool(TEST_DIRS & {s.lower() for s in pp.parts[:-1]})
                or bool(TEST_WORD_RE.search(pp.name.lower()))
                or bool(TEST_CAMEL_RE.search(pp.name)) or pp.name.endswith(".t"))

    def is_source(self, p):
        return PurePosixPath(p).suffix.lower() in SOURCE_EXT

    def _plan(self, oracle: str, has_oracle: bool) -> Plan:
        return Plan(
            image=self.image, oracle=oracle, compile_fail_re=COMPILE_FAIL_RE,
            build=["true"], existing=None, agent_tests={}, warm=[],
            extra_apt=self.extra_apt,
            notes={"setup_mode": "agent", **({} if has_oracle else {"no_upstream_oracle": True})},
        )

    def plan(self, baseline, tests, code, test_diff, siblings):
        # The upstream tests are overlaid and the project's whole suite (as the
        # agent's setup found it) is the oracle: it must fail on the vulnerable
        # tree and pass on the fix.
        return self._plan(SETUP_ORACLE, True)

    def env_plan(self, baseline, code):
        return self._plan("", False)


# Native toolchains on top of buildpack-deps (gcc, make, autotools, pkg-config,
# git, curl and common -dev libraries). The agent apt-installs whatever else.
NATIVE_APT = ("cmake", "meson", "ninja-build", "bison", "flex", "gettext", "autopoint",
              "clang", "llvm", "gdb", "valgrind", "python3", "python3-pip")

SETUP_ADAPTERS: tuple[AgentSetupAdapter, ...] = (
    AgentSetupAdapter("native", "git-generic", "buildpack-deps:bookworm", extra_apt=NATIVE_APT,
                      dep_files=("vcpkg.json", "conanfile.txt", "conanfile.py", "Cargo.lock",
                                 "go.sum", "package-lock.json", "yarn.lock", "composer.lock")),
    AgentSetupAdapter("dotnet", "lang:dotnet", "mcr.microsoft.com/dotnet/sdk:8.0",
                      dep_files=("packages.lock.json", "packages.config", "Directory.Packages.props")),
    AgentSetupAdapter("elixir", "lang:elixir", "elixir:1.16", dep_files=("mix.lock",)),
)


# Builder languages whose layout their adapter cannot handle (no go.mod at the
# root, unknown JS runner, no phpunit, Gradle without a wrapper...): the agent
# sets the project up instead, starting from that language's usual image.
FALLBACK_IMAGES = {
    "go": "golang:1.22-bookworm", "python": "python:3.11-bookworm",
    "javascript": "node:20-bookworm", "java": "maven:3.9-eclipse-temurin-17",
    "rust": "rust:1-bookworm", "php": "php:8.2-cli-bookworm", "ruby": "ruby:3.2-bookworm",
}


class FallbackSetupAdapter(AgentSetupAdapter):
    """A language adapter's file rules with agent setup instead of its builder."""

    def __init__(self, base: Adapter) -> None:
        super().__init__(base.name, base.track,
                         FALLBACK_IMAGES.get(base.name, "buildpack-deps:bookworm"))
        self._base = base

    def is_test(self, p):
        return self._base.is_test(p)

    def is_source(self, p):
        return self._base.is_source(p)

    def is_dep_file(self, p):
        return self._base.is_dep_file(p)


def fallback_for(adapter: Adapter) -> AgentSetupAdapter:
    return adapter if isinstance(adapter, AgentSetupAdapter) else FallbackSetupAdapter(adapter)
