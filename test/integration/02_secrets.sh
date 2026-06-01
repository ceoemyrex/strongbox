#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 02_secrets: Write, read, and version retrieval"

[[ -n "${ROOT_TOKEN}" ]] || { fail "STRONGBOX_ROOT_TOKEN required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

code="$(curl -sk -o /tmp/sb_w1.json -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/app/db" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"user":"admin","password":"s3cr3t"}}')"
[[ "${code}" == "201" ]] && pass "write v1 (201)" || fail "write v1 returned ${code}"
grep -q '"version":1' /tmp/sb_w1.json && pass "version 1 returned" || fail "version 1 not returned"

code="$(curl -sk -o /tmp/sb_w2.json -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/app/db" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"user":"admin","password":"newpass"}}')"
[[ "${code}" == "201" ]] && pass "write v2 (201)" || fail "write v2 returned ${code}"
grep -q '"version":2' /tmp/sb_w2.json && pass "version 2 returned" || fail "version 2 not returned"

code="$(curl -sk -o /tmp/sb_r.json -w "%{http_code}" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" "${BASE_URL}/v1/secrets/app/db")"
[[ "${code}" == "200" ]] && pass "read latest (200)" || fail "read latest returned ${code}"
grep -q '"password":"newpass"' /tmp/sb_r.json && pass "latest is v2" || fail "latest is not v2"

code="$(curl -sk -o /tmp/sb_rv1.json -w "%{http_code}" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" "${BASE_URL}/v1/secrets/app/db?version=1")"
[[ "${code}" == "200" ]] && pass "read v1 (200)" || fail "read v1 returned ${code}"
grep -q '"password":"s3cr3t"' /tmp/sb_rv1.json && pass "v1 has original password" || fail "v1 data mismatch"

code="$(curl -sk -o /tmp/sb_rv2.json -w "%{http_code}" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" "${BASE_URL}/v1/secrets/app/db?version=2")"
[[ "${code}" == "200" ]] && pass "read v2 (200)" || fail "read v2 returned ${code}"
grep -q '"password":"newpass"' /tmp/sb_rv2.json && pass "v2 has new password" || fail "v2 data mismatch"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
