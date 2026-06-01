#!/usr/bin/env bash
# test/integration/09_audit_tamper.sh — grading scenario: Flip one byte verify exits non-zero names bad entry
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

echo "==> 09_audit_tamper: Flip one byte verify exits non-zero names bad entry"

# TODO: implement steps for this scenario.
# Each step should call pass or fail.

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
