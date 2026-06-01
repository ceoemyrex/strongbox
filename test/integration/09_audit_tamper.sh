#!/usr/bin/env bash
# test/integration/09_audit_tamper.sh — grading scenario: Flip one byte verify exits non-zero names bad entry
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-https://localhost}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
AUDIT_LOG="${STRONGBOX_AUDIT_LOG:-/var/log/strongbox/audit.log}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }
expect_http() {
  local label="$1" want="$2" got="$3"
  [[ "$got" == "$want" ]] && pass "$label (HTTP $got)" || fail "$label — want $want got $got"
}

echo "==> 09_audit_tamper: Flip one byte verify exits non-zero names bad entry"

[[ -n "${STRONGBOX_AUDIT_HMAC_KEY:-}" ]] || fail "STRONGBOX_AUDIT_HMAC_KEY is required"
[[ -f "${AUDIT_LOG}" ]] || fail "audit log not found at ${AUDIT_LOG}"

tmp_log="$(mktemp)"
tmp_out="$(mktemp)"
tmp_err="$(mktemp)"
trap 'rm -f "${tmp_log}" "${tmp_out}" "${tmp_err}"' EXIT

cp "${AUDIT_LOG}" "${tmp_log}"

if bin/strongbox-verify "${tmp_log}" >"${tmp_out}" 2>"${tmp_err}"; then
  pass "original audit log verifies"
else
  cat "${tmp_err}" >&2
  fail "original audit log should verify"
fi

perl -0pi -e 's/"op":"/"op":"tampered-/' "${tmp_log}"

if bin/strongbox-verify "${tmp_log}" >"${tmp_out}" 2>"${tmp_err}"; then
  fail "tampered audit log should fail verification"
else
  pass "tampered audit log exits non-zero"
fi

grep -q 'TAMPERED: audit entry index' "${tmp_err}" \
  && pass "verifier named bad entry index" \
  || fail "verifier did not name bad entry index"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
