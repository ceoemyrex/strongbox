#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 01_unseal: Submit K shares, verify sealed-to-unsealed transition"

[[ -f /tmp/sb_init.json ]] || { fail "run 00_init.sh first"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

SHARE1="$(python3 -c "import json; print(json.load(open('/tmp/sb_init.json'))['shares'][0])")"
SHARE2="$(python3 -c "import json; print(json.load(open('/tmp/sb_init.json'))['shares'][1])")"

code="$(curl -sk -o /tmp/sb_unseal1.json -w "%{http_code}" -X POST "${BASE_URL}/v1/sys/unseal" \
  -H "Content-Type: application/json" -d "{\"share\":\"${SHARE1}\"}")"
[[ "${code}" == "200" ]] && pass "first share accepted (200)" || fail "first share returned ${code}"
grep -q '"progress":"1/2"' /tmp/sb_unseal1.json && pass "progress 1/2" || fail "unexpected progress"

code="$(curl -sk -o /tmp/sb_unseal2.json -w "%{http_code}" -X POST "${BASE_URL}/v1/sys/unseal" \
  -H "Content-Type: application/json" -d "{\"share\":\"${SHARE2}\"}")"
[[ "${code}" == "200" ]] && pass "second share accepted (200)" || fail "second share returned ${code}"
grep -q '"sealed":false' /tmp/sb_unseal2.json && pass "vault unsealed" || fail "vault still sealed"

code="$(curl -sk -o /tmp/sb_health.json -w "%{http_code}" "${BASE_URL}/v1/sys/health")"
grep -q '"sealed":false' /tmp/sb_health.json && pass "health confirms unsealed" || fail "health still shows sealed"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
