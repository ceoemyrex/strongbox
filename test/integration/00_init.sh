#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 00_init: Cluster boots sealed, init returns shares + root token"

code="$(curl -sk -o /tmp/sb_health.json -w "%{http_code}" "${BASE_URL}/v1/sys/health")"
[[ "${code}" == "200" ]] && pass "health endpoint responds" || fail "health returned ${code}"
grep -q '"sealed":true' /tmp/sb_health.json && pass "cluster boots sealed" || fail "cluster not sealed on boot"

code="$(curl -sk -o /tmp/sb_secret.json -w "%{http_code}" -H "Authorization: Bearer fake" "${BASE_URL}/v1/secrets/app/db")"
[[ "${code}" == "503" ]] && pass "secret read blocked while sealed (503)" || fail "sealed read returned ${code}"

code="$(curl -sk -o /tmp/sb_init.json -w "%{http_code}" -X POST "${BASE_URL}/v1/sys/init" -H "Content-Type: application/json")"
[[ "${code}" == "200" ]] && pass "init returned 200" || fail "init returned ${code}"

ROOT_TOKEN="$(python3 -c "import json; print(json.load(open('/tmp/sb_init.json'))['root_token'])" 2>/dev/null)"
[[ -n "${ROOT_TOKEN}" ]] && pass "root_token present" || fail "root_token missing"

SHARES="$(python3 -c "import json; print(len(json.load(open('/tmp/sb_init.json'))['shares']))" 2>/dev/null)"
[[ "${SHARES}" == "3" ]] && pass "3 shares returned" || fail "expected 3 shares, got ${SHARES}"

export STRONGBOX_ROOT_TOKEN="${ROOT_TOKEN}"
echo "    ROOT_TOKEN=${ROOT_TOKEN}"
echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
