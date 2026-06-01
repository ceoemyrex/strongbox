#!/usr/bin/env bash
set -euo pipefail

ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 09_audit_tamper: Flip one byte, verify exits non-zero, names bad entry"

[[ -n "${STRONGBOX_AUDIT_HMAC_KEY:-}" ]] || { fail "STRONGBOX_AUDIT_HMAC_KEY required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

MSYS_NO_PATHCONV=1 docker exec strongbox-node-1 bash -c '
  cp /var/log/strongbox/audit.log /tmp/audit_clean.log
  cp /var/log/strongbox/audit.log /tmp/audit_tamper.log
'

RESULT="$(MSYS_NO_PATHCONV=1 docker exec -e STRONGBOX_AUDIT_HMAC_KEY="${STRONGBOX_AUDIT_HMAC_KEY}" \
  strongbox-node-1 /opt/strongbox/bin/strongbox-verify /tmp/audit_clean.log 2>&1)" && \
  pass "clean audit log verifies" || fail "clean audit log failed verification: ${RESULT}"

MSYS_NO_PATHCONV=1 docker exec strongbox-node-1 bash -c "sed -i '1s/read/XXXX/' /tmp/audit_tamper.log"

RESULT="$(MSYS_NO_PATHCONV=1 docker exec -e STRONGBOX_AUDIT_HMAC_KEY="${STRONGBOX_AUDIT_HMAC_KEY}" \
  strongbox-node-1 /opt/strongbox/bin/strongbox-verify /tmp/audit_tamper.log 2>&1)" && \
  fail "tampered log should fail verification" || pass "tampered log exits non-zero"

echo "${RESULT}" | grep -q 'TAMPERED: audit entry index' \
  && pass "verifier names bad entry index" \
  || fail "verifier did not name the bad entry"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
