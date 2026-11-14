#!/usr/bin/env bash
# Hidden oracle: overlay the fix commit's tests onto the tree under test and
# run only them. Exit 0 iff they pass. Exit 3 = the tests did not compile/load
# (not a behavioural failure).
set -uo pipefail
cp -r "${ORACLE_DIR:-/opt/hidden/oracle}/files/." .
out=$( { bash build.sh && ./build/regression_test ; } 2>&1 ); rc=$?
printf '%s\n' "$out"
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -qE 'error:|undefined reference'; then
  echo "ORACLE_BUILD_FAILED"; exit 3
fi
exit $rc
