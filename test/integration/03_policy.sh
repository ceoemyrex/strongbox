#!/usr/bin/env bash
# test/integration/03_policy.sh — grading scenario: Token scoped to read on secret/app/* — 200 and 403 checks
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

echo "==> 03_policy: Token scoped to read on secret/app/* — 200 and 403 checks"

TEST_USERNAME="${STRONGBOX_TEST_USERNAME:-policy-reader}"
TEST_PASSWORD="${STRONGBOX_TEST_PASSWORD:-policy-reader-password}"

[[ -n "${ROOT_TOKEN}" ]] || fail "STRONGBOX_ROOT_TOKEN is required"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/policies/app-read" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"rules":[{"path":"secret/app/*","capabilities":["read"]}]}')"
expect_http "root creates read-only policy" "201" "${code}"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/secret/app/db" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":"policy-value"}')"
expect_http "root seeds readable secret" "201" "${code}"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  -X POST "${BASE_URL}/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USERNAME}\",\"password\":\"${TEST_PASSWORD}\"}")"
expect_http "policy user login succeeds" "200" "${code}"
TOKEN="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' /tmp/strongbox_policy_body.json)"
[[ -n "${TOKEN}" ]] && pass "login returned token" || fail "login did not return token"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  "${BASE_URL}/v1/secrets/secret/app/db" \
  -H "Authorization: Bearer ${TOKEN}")"
expect_http "read under secret/app/* succeeds" "200" "${code}"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/secret/app/db" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":"blocked-write"}')"
expect_http "write under read-only policy is forbidden" "403" "${code}"

code="$(curl -sk -o /tmp/strongbox_policy_body.json -w "%{http_code}" \
  "${BASE_URL}/v1/secrets/secret/other/x" \
  -H "Authorization: Bearer ${TOKEN}")"
expect_http "read outside prefix is forbidden" "403" "${code}"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
