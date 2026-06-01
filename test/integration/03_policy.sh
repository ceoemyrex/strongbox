#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 03_policy: Token scoped to read on secret/app/* — 200 and 403 checks"

[[ -n "${ROOT_TOKEN}" ]] || { fail "STRONGBOX_ROOT_TOKEN required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/policies/app-reader" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"path":"secret/app/*","capabilities":["read"]}]}')"
[[ "${code}" == "201" ]] && pass "policy created (201)" || fail "policy create returned ${code}"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/users/policyuser" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"password":"policypass","policies":["app-reader"]}')"
[[ "${code}" == "201" ]] && pass "user created (201)" || fail "user create returned ${code}"

code="$(curl -sk -o /tmp/sb_login.json -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"policyuser","password":"policypass"}')"
[[ "${code}" == "200" ]] && pass "login (200)" || fail "login returned ${code}"
USR_TOKEN="$(python3 -c "import json; print(json.load(open('/tmp/sb_login.json'))['token'])" 2>/dev/null)"
[[ -n "${USR_TOKEN}" ]] && pass "token returned" || fail "no token in login response"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${USR_TOKEN}" "${BASE_URL}/v1/secrets/app/db")"
[[ "${code}" == "200" ]] && pass "read secret/app/db (200)" || fail "read app/db returned ${code}"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/app/db" \
  -H "Authorization: Bearer ${USR_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"x":1}}')"
[[ "${code}" == "403" ]] && pass "write secret/app/db (403)" || fail "write app/db returned ${code}"

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${USR_TOKEN}" "${BASE_URL}/v1/secrets/other/x")"
[[ "${code}" == "403" ]] && pass "read secret/other/x (403)" || fail "read other/x returned ${code}"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
