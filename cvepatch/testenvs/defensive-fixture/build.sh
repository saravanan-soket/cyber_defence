#!/usr/bin/env bash
# Build the defensive fixture image. Stages a minimal build context so the
# multi-GB repo (data/, runs/, .venv/) is never sent to the docker daemon.
set -euo pipefail
cd "$(dirname "$0")"

REPO_ROOT="$(cd ../.. && pwd)"
TAG="${1:-local/defensive-fixture:latest}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Baseline source + task manifest.
cp -r baseline "$STAGE/baseline"
rm -rf "$STAGE/baseline/build"
cp -r task "$STAGE/task"

# The cvepatch.core subtree (+ the trivial package __init__), which is
# all the in-image grader/server need. No heavy runner deps come along.
mkdir -p "$STAGE/pkg/cvepatch"
cp "$REPO_ROOT/cvepatch/__init__.py" "$STAGE/pkg/cvepatch/__init__.py"
cp -r "$REPO_ROOT/cvepatch/core" "$STAGE/pkg/cvepatch/core"
find "$STAGE/pkg" -name '__pycache__' -type d -prune -exec rm -rf {} +

cp Dockerfile "$STAGE/Dockerfile"

docker build -t "$TAG" "$STAGE"
echo "built $TAG"
