#!/usr/bin/env bash
# Build the cvepatch fixture image from a minimal staged context (no hidden/).
set -euo pipefail
cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
TAG="${1:-local/cvepatch-fixture:latest}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -r baseline public Dockerfile "$STAGE/"
rm -rf "$STAGE/baseline/build"
mkdir -p "$STAGE/pkg/cvepatch"
cp "$REPO_ROOT/cvepatch/__init__.py" "$STAGE/pkg/cvepatch/__init__.py"
cp -r "$REPO_ROOT/cvepatch/core" "$STAGE/pkg/cvepatch/core"
find "$STAGE/pkg" -name '__pycache__' -type d -prune -exec rm -rf {} +
docker build -t "$TAG" "$STAGE"
echo "built $TAG"
