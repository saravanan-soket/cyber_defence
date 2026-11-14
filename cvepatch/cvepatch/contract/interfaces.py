"""RL env interface registry.

Each env declares an `interface` string from this registry. The interface
captures what an env IS (tools it must expose, submission shape it accepts,
how grading is computed, what capability flags are meaningful) without
constraining what target software it runs against.

Status today:
  - The interface name is stored on every `runs` row for audit / future
    enforcement.
  - The registry is pre-populated with the interfaces we expect long-term —
    so adding a new env type is "set interface: rl.mcp.X" in the config and
    the registry already knows the contract.
  - The actual-tool-surface validator (`cvepatch validate-image`) checks
    a registered env against its declared interface; that catalog + manifest
    plumbing is in place. The interface registry itself is still primarily
    a typed namespace — call sites read from it, but enforcement is opt-in.

Naming convention `rl.mcp.<task>.<version>`:
  - `rl.mcp` — RL environment, MCP-served
  - `<task>` — what the env is FOR (binary_patch, ...)
  - `<version>` — semver-ish; bump when the contract changes incompatibly
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

GraderKind = Literal["mcp_tool", "cli_oneshot"]
SubmissionKind = Literal["patch"]


@dataclass(frozen=True)
class Interface:
    """One interface contract."""

    name: str
    description: str
    base: str | None = None                   # parent interface, for shape inheritance / docs
    mcp_tools: tuple[str, ...] = ()           # tools the server is expected to expose
    capability_flags: tuple[str, ...] = ()    # bitmap keys the grader emits (if any)
    submission_kind: SubmissionKind | None = None
    grader_kind: GraderKind = "mcp_tool"
    grader_tool: str | None = "grade"         # MCP tool name when grader_kind=='mcp_tool'
    grader_command: tuple[str, ...] | None = None  # argv when grader_kind=='cli_oneshot'
    notes: str = ""


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

RL_MCP_BASE = Interface(
    name="rl.mcp.base.v1",
    description="Base contract: filesystem + shell exec. Not used directly; "
                "a parent class for task-specific interfaces.",
    mcp_tools=("setup", "exec", "list_directory", "read_file", "write_file"),
)


# ---------------------------------------------------------------------------
# Defensive family (vulnerability detection + patch verification)
# ---------------------------------------------------------------------------

RL_MCP_VULNERABILITY_DEFENSE = Interface(
    name="rl.mcp.vulnerability_defense.v1",
    description="Defensive vulnerability-defense task. The agent investigates "
                "a known vulnerability, identifies its root cause, and submits "
                "a unified-diff patch; a TRUSTED post-episode cli_oneshot "
                "grader independently builds the candidate and runs regression "
                "+ existing tests to produce a deterministic verdict. grade() "
                "is NOT exposed to the agent (reward-hacking guard). "
                "capability_flags are the DEFENSIVE dimensions, deliberately "
                "disjoint from the offensive 16-flag bitmap, and scored by the "
                "defensive policy (see runner/scoring.py), never the offensive "
                "capability sum.",
    base="rl.mcp.base.v1",
    mcp_tools=(
        "setup", "read_file", "list_directory", "search_code", "inspect_diff",
        "run_static_analysis", "run_tests", "apply_patch", "write_file",
        "run_command", "submit_fix", "submit_patch", "submit_report",
        # Reserved post-episode grading tool. MUST be an evaluation_tool in the
        # manifest (disjoint from episode_tools) so the loop filters it out of
        # the agent's surface.
        "grade_defensive",
    ),
    capability_flags=(
        "detection_correct",
        "root_cause_supported",
        "patch_format_valid",
        "candidate_build_passed",
        "baseline_reproduced",
        "regression_test_passed",
        "existing_tests_passed",
        "security_checks_passed",
        "patch_provenance_verified",
        "validation_reproducible",
        "false_positive",
        "infrastructure_failure",
        # cvepatch verifier checks (verifier/verify.py); the tier is derived
        # from these.
        "fix_applies",
        "test_applies",
        "agent_test_fails_on_vuln",
        "agent_test_passes_on_fix",
        "upstream_test_fails_on_vuln",
        "upstream_test_passes_on_fix",
        "agent_test_passes_on_upstream_fix",
        "agent_test_passes_on_fixed_release",
    ),
    submission_kind="patch",
    grader_kind="cli_oneshot",
    grader_tool=None,
    grader_command=None,
    notes="Defensive task; graded by an independent executable pipeline, "
          "never an LLM judge. task_type='binary_patch' in the env manifest.",
)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, Interface] = {
    iface.name: iface
    for iface in (
        RL_MCP_BASE,
        RL_MCP_VULNERABILITY_DEFENSE,
    )
}


def lookup(name: str) -> Interface | None:
    """Return the Interface for `name`, or None if unknown."""
    return REGISTRY.get(name)


def all_names() -> list[str]:
    """Sorted list of all known interface names."""
    return sorted(REGISTRY.keys())


def is_known(name: str) -> bool:
    return name in REGISTRY
