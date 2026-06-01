#!/usr/bin/env bash
# test/integration/06_pg_down.sh — grading scenario: Stop Postgres wait past TTL restart verify cleanup
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-https://localhost}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }
expect_http() {
  local label="$1" want="$2" got="$3"
  [[ "$got" == "$want" ]] && pass "$label (HTTP $got)" || fail "$label — want $want got $got"
}

echo "==> 06_pg_down: Stop Postgres wait past TTL restart verify cleanup"

# TODO: implement steps for this scenario.
# Each step should call pass or fail.

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
