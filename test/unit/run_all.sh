#!/usr/bin/env bash
# test/unit/run_all.sh — run every unit test in the seal/crypto/shamir scope.
# This is what you should run before every commit. It's quick (~5s total) and
# does not need Docker, Postgres, or any external service.
#
# Usage:
#   bash test/unit/run_all.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO}"

PASS=0
FAIL=0
FAILED_SUITES=()

run() {
  local label="$1"
  local cmd="$2"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  ${label}"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if bash -c "${cmd}"; then
    PASS=$(( PASS + 1 ))
  else
    FAIL=$(( FAIL + 1 ))
    FAILED_SUITES+=("${label}")
  fi
}

run "shamir.py — GF(2⁸) and split/reconstruct"   "python3 test/unit/test_shamir.py"
run "crypto.sh — envelope encryption"            "bash test/unit/test_crypto.sh"
run "seal.sh — seal/unseal state machine"        "bash test/unit/test_seal.sh"
run "http.sh — /sys/* handlers"                  "bash test/unit/test_sys_handlers.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Summary: ${PASS} suites passed / ${FAIL} suites failed"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "${FAIL}" -gt 0 ]; then
  echo ""
  echo "Failed suites:"
  for s in "${FAILED_SUITES[@]}"; do echo "  - ${s}"; done
  exit 1
fi
