# cvepatch fixture: the strbuf off-by-one in the standard task-bundle layout.
# Only baseline/ and public/ enter the image; hidden/ (upstream test, fix,
# full task) is mounted into the verifier's container only.
FROM debian:bookworm-slim

RUN printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4 \
    && apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev bash diffutils patch git python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir "jsonschema>=4.20" "pyyaml>=6.0" "mcp>=1.1,<2" \
    && /opt/venv/bin/python -c "import sysconfig;open(sysconfig.get_paths()['purelib']+'/defensive.pth','w').write('/opt/pkg\n')"

COPY pkg/ /opt/pkg/
COPY baseline/ /opt/defensive/baseline/
COPY public/ /opt/defensive/task/

RUN mkdir -p /rlenv/workspace && cp -r /opt/defensive/baseline /rlenv/src \
    && useradd --uid 1000 --create-home --shell /bin/bash agent \
    && chown -R agent /rlenv/workspace \
    && chmod -R a-w /rlenv/src && chmod -R a+rX /opt/defensive /opt/pkg

USER agent
ENV DEF_SOURCE_DIR=/rlenv/src DEF_WORKSPACE_DIR=/rlenv/workspace \
    DEF_TASK_PATH=/opt/defensive/task/defensive_task.json \
    DEF_ALLOWED_TESTS='{}'
CMD ["/opt/venv/bin/python", "-m", "cvepatch.core.mcp_server.tools"]
