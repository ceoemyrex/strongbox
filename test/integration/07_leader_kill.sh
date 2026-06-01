#!/usr/bin/env bash
# test/integration/07_leader_kill.sh — grading scenario: Kill leader mid-write verify durability under new leader
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

echo "==> 07_leader_kill: Kill leader mid-write verify durability under new leader"

# TODO: implement steps for this scenario.
# Each step should call pass or fail.

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
