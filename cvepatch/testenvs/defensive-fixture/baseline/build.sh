#!/usr/bin/env bash
# Build the strbuf fixture library + its test binaries. Fast (seconds), no
# network, no external deps beyond a C compiler. Produces ./build/.
set -euo pipefail
cd "$(dirname "$0")"

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O0 -g -Wall -Isrc}"

mkdir -p build
$CC $CFLAGS -c src/strbuf.c -o build/strbuf.o
$CC $CFLAGS tests/regression_test.c build/strbuf.o -o build/regression_test
$CC $CFLAGS tests/functional_test.c build/strbuf.o -o build/functional_test
echo "build: ok"
