"""Task-container side of cvepatch: ingestion, task generation, the agent's
MCP tools, the validation pipeline and the post-episode verifier.

Self-contained (stdlib + yaml/jsonschema only) so it can be copied into task
images as-is. Key invariants:
  * Verdicts come only from executable tests + versioned rules
    (`validation/pipeline.py`); no LLM judges correctness.
  * A build succeeding never advances a task to REPRODUCIBLE or
    PATCH_VERIFIED.
  * Missing CVE / fix-commit / patch metadata is represented explicitly;
    nothing is invented.
"""

from __future__ import annotations

# Defensive score schema version. Bump on any incompatible change to the
# set/meaning of the dimensions in `verifier.metrics`.
DEFENSIVE_SCORE_SCHEMA_VERSION = "1"

# Defensive task manifest schema version (mirrors defensive_task.schema.json).
DEFENSIVE_TASK_SCHEMA_VERSION = "1"

# The interface name this package implements (registered in
# cvepatch.contract.interfaces).
DEFENSIVE_INTERFACE = "rl.mcp.vulnerability_defense.v1"
