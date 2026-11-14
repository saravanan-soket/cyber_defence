#!/usr/bin/env bash
# Build the defensive layer on top of an already-built bench-v8 bug image.
#   bash testenvs/defensive-v8/build.sh <bench-v8-image> [tag]
set -euo pipefail
cd "$(dirname "$0")"
BASE="${1:?usage: build.sh <bench-v8-image> [tag]}"
TAG="${2:-local/v8-defensive:latest}"
[ -f regression/run.sh ] || { echo "missing regression/run.sh (see regression/README.md)"; exit 1; }
REPO_ROOT="$(cd ../.. && pwd)"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/pkg/cvepatch"
cp "$REPO_ROOT/cvepatch/__init__.py" "$STAGE/pkg/cvepatch/"
cp -r "$REPO_ROOT/cvepatch/core" "$STAGE/pkg/cvepatch/core"
find "$STAGE/pkg" -name __pycache__ -type d -prune -exec rm -rf {} +
cp -r task regression "$STAGE/"
cp Dockerfile.defensive "$STAGE/Dockerfile"
docker build --build-arg BASE_IMAGE="$BASE" -t "$TAG" "$STAGE"
echo "built $TAG"
