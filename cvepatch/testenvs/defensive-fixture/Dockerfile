# Defensive fixture env image.
#
# Build via ./build.sh (it stages a minimal context: the baseline source, the
# task manifest, and the cvepatch.core subtree). Fast — seconds, no
# V8, no network.
#
# Layout / trust boundary:
#   /opt/defensive/baseline  trusted source baseline     (root-owned, world-readable)
#   /opt/defensive/task      defensive task manifest     (root-owned)
#   /opt/pkg/cvepatch    grader + pipeline code       (root-owned)
#   /rlenv/src               read-only source for agent  (chmod a-w)
#   /rlenv/workspace         writable patch workspace    (owned by agent)
#
# Episode: the MCP server (ENTRYPOINT) runs as the unprivileged `agent` user.
# Grading: the runner invokes `python -m
# cvepatch.core.verifier.deterministic_grader ...` in a FRESH container
# of this image (so the agent's container state is irrelevant), reading the
# submitted patch from the read-only /run mount.
FROM debian:bookworm-slim

# Force apt over IPv4: some resolvers hand back AAAA-only records for the
# Debian mirrors, and a build host without IPv6 egress then hangs on
# "Get:1 ... InRelease". ForceIPv4 keeps the build portable.
RUN printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4 \
    && apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev bash diffutils patch git \
        python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Grader deps only (no litellm/anthropic/etc. — the defensive grader subtree
# needs just jsonschema + pyyaml; mcp for the server).
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "jsonschema>=4.20" "pyyaml>=6.0" "mcp>=1.1,<2"

# cvepatch.core package (staged by build.sh into ./pkg/).
COPY pkg/ /opt/pkg/

# Trusted baseline + task manifest (root-owned).
COPY baseline/ /opt/defensive/baseline/
COPY task/ /opt/defensive/task/

# Agent-facing read-only source + writable workspace.
RUN mkdir -p /rlenv/workspace \
    && cp -r /opt/defensive/baseline /rlenv/src \
    && rm -rf /rlenv/src/build \
    && useradd --uid 1000 --create-home --shell /bin/bash agent \
    && chown -R agent:agent /rlenv/workspace \
    && chmod -R a-w /rlenv/src

USER agent

# The legacy benchmark tools (run_tests, run_static_analysis, submit_patch).
ENV DEF_LEGACY_TOOLS=1
ENV PYTHONPATH=/opt/pkg \
    PATH=/opt/venv/bin:$PATH \
    DEF_SOURCE_DIR=/rlenv/src \
    DEF_WORKSPACE_DIR=/rlenv/workspace \
    DEF_TASK_PATH=/opt/defensive/task/defensive_task.json

# Default: serve the defensive MCP server on stdio. Uses CMD (not ENTRYPOINT)
# so the post-episode cli_oneshot grader can REPLACE it with its own argv:
# `docker run <img>` (no args) runs the MCP server for the episode, while
# `docker run <img> python -m ...grader ...` overrides CMD for grading. An
# exec-form ENTRYPOINT would instead APPEND the grader argv to the server
# invocation, launching the MCP server at grade time and emitting no verdict.
CMD ["/opt/venv/bin/python", "-m", "cvepatch.core.mcp_server.tools"]
