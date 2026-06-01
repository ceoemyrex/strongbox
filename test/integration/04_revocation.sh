#!/usr/bin/env bash
# test/integration/04_revocation.sh — grading scenario: Create token revoke token next request must be 401
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

echo "==> 04_revocation: Create token revoke token next request must be 401"

TEST_USERNAME="${STRONGBOX_TEST_USERNAME:-policy-reader}"
TEST_PASSWORD="${STRONGBOX_TEST_PASSWORD:-policy-reader-password}"

[[ -n "${ROOT_TOKEN}" ]] || fail "STRONGBOX_ROOT_TOKEN is required"

code="$(curl -sk -o /tmp/strongbox_revoke_body.json -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USERNAME}\",\"password\":\"${TEST_PASSWORD}\"}")"
expect_http "login creates token" "200" "${code}"
TOKEN="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/strongbox_revoke_body.json)"
[[ -n "${TOKEN}" ]] && pass "login returned token" || fail "login did not return token"

code="$(curl -sk -o /tmp/strongbox_revoke_body.json -w "%{http_code}" \
  "${BASE_URL}/v1/auth/self" \
  -H "Authorization: Bearer ${TOKEN}")"
expect_http "fresh token works before revoke" "200" "${code}"

code="$(curl -sk -o /tmp/strongbox_revoke_body.json -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/revoke" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${TOKEN}\"}")"
expect_http "root revokes token" "204" "${code}"

code="$(curl -sk -o /tmp/strongbox_revoke_body.json -w "%{http_code}" \
  "${BASE_URL}/v1/auth/self" \
  -H "Authorization: Bearer ${TOKEN}")"
expect_http "revoked token fails immediately" "401" "${code}"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
