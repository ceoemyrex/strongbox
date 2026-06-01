#!/usr/bin/env bash
# test/integration/02_secrets.sh — grading scenario: Write read and version retrieval
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

echo "==> 02_secrets: Write read and version retrieval"

[[ -n "${ROOT_TOKEN}" ]] || fail "STRONGBOX_ROOT_TOKEN is required"

write_secret() {
  local value="$1"
  curl -sk -o /tmp/strongbox_secret_body.json -w "%{http_code}" \
    -X PUT "${BASE_URL}/v1/secrets/secret/app/db" \
    -H "Authorization: Bearer ${ROOT_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"data\":\"${value}\"}"
}

read_secret() {
  local suffix="${1:-}"
  curl -sk -o /tmp/strongbox_secret_body.json -w "%{http_code}" \
    "${BASE_URL}/v1/secrets/secret/app/db${suffix}" \
    -H "Authorization: Bearer ${ROOT_TOKEN}"
}

code="$(write_secret "postgres://v1")"
expect_http "first write creates version" "201" "${code}"
grep -q '"version":1' /tmp/strongbox_secret_body.json && pass "first write returned version 1" || fail "first write did not return version 1"

code="$(write_secret "postgres://v2")"
expect_http "second write creates version" "201" "${code}"
grep -q '"version":2' /tmp/strongbox_secret_body.json && pass "second write returned version 2" || fail "second write did not return version 2"

code="$(read_secret "")"
expect_http "latest read succeeds" "200" "${code}"
grep -q '"data":"postgres://v2"' /tmp/strongbox_secret_body.json && pass "latest read returned v2" || fail "latest read did not return v2"

code="$(read_secret "?version=1")"
expect_http "version 1 read succeeds" "200" "${code}"
grep -q '"data":"postgres://v1"' /tmp/strongbox_secret_body.json && pass "version 1 read returned v1" || fail "version 1 read did not return v1"

code="$(read_secret "?version=2")"
expect_http "version 2 read succeeds" "200" "${code}"
grep -q '"data":"postgres://v2"' /tmp/strongbox_secret_body.json && pass "version 2 read returned v2" || fail "version 2 read did not return v2"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
