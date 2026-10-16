#!/usr/bin/env bash
# Run a cargo test command and fail when too few tests ran. A filter that
# matches nothing (a renamed test, an --exact typo) or a run whose tests are
# all ignored or filtered out otherwise passes as "ok" with 0 tests.
#
#   bash scripts/require_tests.sh [--min N] cargo test ... -- [filters]
#
# N (default 1) is the least number of passed tests, summed over every test
# binary the command runs.
set -euo pipefail

min=1
if [ "${1:-}" = "--min" ]; then
  min="$2"
  shift 2
fi
case "$min" in
  '' | *[!0-9]*) echo "require_tests.sh: --min needs a number, got '$min'" >&2; exit 2 ;;
esac
if [ "$#" -eq 0 ]; then
  echo "usage: require_tests.sh [--min N] cargo test ..." >&2
  exit 2
fi

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
# pipefail: a failing test command fails here, before the count.
"$@" 2>&1 | tee "$log"
passed="$(sed -n 's/^test result: [A-Za-z]*\. \([0-9][0-9]*\) passed;.*/\1/p' "$log" \
  | awk '{ n += $1 } END { print n + 0 }')"
if [ "$passed" -lt "$min" ]; then
  echo "::error::$passed tests ran, at least $min expected: a filter matches nothing, or the tests are ignored ($*)"
  exit 1
fi
echo "$passed tests ran (at least $min expected)"
