#!/usr/bin/env bash
# Build the strbuf library and one binary per tests/*.c into ./build/.
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O0 -g -Wall -Isrc}"
mkdir -p build
$CC $CFLAGS -c src/strbuf.c -o build/strbuf.o
for t in tests/*.c; do
  $CC $CFLAGS "$t" build/strbuf.o -o "build/$(basename "${t%.c}")"
done
echo "build: ok"
