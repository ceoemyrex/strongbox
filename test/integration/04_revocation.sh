#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 04_revocation: Create token, revoke, next request must be 401"

[[ -n "${ROOT_TOKEN}" ]] || { fail "STRONGBOX_ROOT_TOKEN required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

curl -sk -o /dev/null -X PUT "${BASE_URL}/v1/users/revokeuser" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"password":"revokepass","policies":["app-reader"]}' 2>/dev/null

code="$(curl -sk -o /tmp/sb_revlogin.json -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"revokeuser","password":"revokepass"}')"
[[ "${code}" == "200" ]] && pass "login (200)" || fail "login returned ${code}"
TOKEN="$(python3 -c "import json; print(json.load(open('/tmp/sb_revlogin.json'))['token'])" 2>/dev/null)"
[[ -n "${TOKEN}" ]] && pass "token returned" || fail "no token"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/v1/auth/self")"
[[ "${code}" == "200" ]] && pass "token works before revoke (200)" || fail "token failed before revoke (${code})"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/revoke" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${TOKEN}\"}")"
[[ "${code}" == "204" ]] && pass "revoke (204)" || fail "revoke returned ${code}"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${TOKEN}" "${BASE_URL}/v1/auth/self")"
[[ "${code}" == "401" ]] && pass "revoked token fails immediately (401)" || fail "revoked token returned ${code}"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
