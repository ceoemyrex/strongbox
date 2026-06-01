#!/usr/bin/env bash
# test/integration/05_dynamic_pg.sh — grading scenario: Read dynamic-postgres/readonly verify pg_roles
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8200}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PG_CONTAINER="${STRONGBOX_PG_CONTAINER:-strongbox-postgres}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

curl_api() {
  local method="$1" path="$2" body="${3:-}"
  local args=(-sk -w "\n%{http_code}" -X "${method}" "${BASE_URL}${path}")
  [[ -n "${ROOT_TOKEN}" ]] && args+=(-H "Authorization: Bearer ${ROOT_TOKEN}")
  [[ -n "${body}" ]] && args+=(-H "Content-Type: application/json" -d "${body}")
  curl "${args[@]}"
}

pg_roles_like_sb() {
  docker exec "${PG_CONTAINER}" psql -U sbadmin -d strongbox -tAc \
    "SELECT rolname FROM pg_roles WHERE rolname LIKE 'sb_%' ORDER BY rolname;" 2>/dev/null \
    | sed '/^$/d'
}

echo "==> 05_dynamic_pg: Read dynamic-postgres/readonly verify pg_roles"

if [[ -z "${ROOT_TOKEN}" ]]; then
  fail "STRONGBOX_ROOT_TOKEN not set — run 00_init.sh first"
  echo "    ${PASS} passed / ${FAIL} failed"
  exit 1
fi

before_roles="$(pg_roles_like_sb || true)"
pass "baseline pg_roles captured (${before_roles:-none})"

response="$(curl_api GET "/v1/dynamic-postgres/readonly")"
body="$(echo "${response}" | sed '$d')"
code="$(echo "${response}" | tail -n1)"

[[ "${code}" == "200" ]] && pass "dynamic-postgres/readonly returned 200" \
  || fail "dynamic-postgres/readonly — want 200 got ${code} body=${body}"

username="$(echo "${body}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('username',''))" 2>/dev/null || true)"
password="$(echo "${body}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('password',''))" 2>/dev/null || true)"
lease_id="$(echo "${body}" | python3 -c "import json,sys; print(json.load(sys.stdin).get('lease',{}).get('lease_id',''))" 2>/dev/null || true)"

[[ -n "${username}" && "${username}" == sb_* ]] && pass "username minted: ${username}" \
  || fail "expected sb_* username, got '${username}'"
[[ -n "${password}" ]] && pass "password returned" || fail "missing password"
[[ -n "${lease_id}" ]] && pass "lease_id returned: ${lease_id}" || fail "missing lease_id"

after_roles="$(pg_roles_like_sb || true)"
echo "${after_roles}" | grep -qx "${username}" \
  && pass "role ${username} visible in pg_roles" \
  || fail "role ${username} not found in pg_roles: ${after_roles:-empty}"

if docker exec "${PG_CONTAINER}" env PGPASSWORD="${password}" \
  psql -U "${username}" -d strongbox -tAc "SELECT count(*) FROM demo_data;" \
  >/dev/null 2>&1; then
  pass "dynamic credential can query demo_data"
else
  fail "dynamic credential could not query demo_data"
fi

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
