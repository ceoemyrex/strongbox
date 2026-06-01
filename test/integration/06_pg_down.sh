#!/usr/bin/env bash
# test/integration/06_pg_down.sh — grading scenario: Stop Postgres wait past TTL restart verify cleanup
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8200}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PG_CONTAINER="${STRONGBOX_PG_CONTAINER:-strongbox-postgres}"
LEASE_TTL="${DYNAMIC_LEASE_TTL:-60}"
REAPER_INTERVAL="${LEASE_REAPER_INTERVAL:-5}"
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

role_exists() {
  local user="$1"
  docker exec "${PG_CONTAINER}" psql -U sbadmin -d strongbox -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname='${user}';" 2>/dev/null | grep -q 1
}

echo "==> 06_pg_down: Stop Postgres wait past TTL restart verify cleanup"

if [[ -z "${ROOT_TOKEN}" ]]; then
  fail "STRONGBOX_ROOT_TOKEN not set — run 00_init.sh first"
  echo "    ${PASS} passed / ${FAIL} failed"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -qx "${PG_CONTAINER}"; then
  fail "Postgres container ${PG_CONTAINER} not running"
  echo "    ${PASS} passed / ${FAIL} failed"
  exit 1
fi

response="$(curl_api GET "/v1/dynamic-postgres/readonly")"
body="$(echo "${response}" | sed '$d')"
code="$(echo "${response}" | tail -n1)"
[[ "${code}" == "200" ]] && pass "minted dynamic credential (HTTP ${code})" \
  || { fail "mint failed — HTTP ${code} body=${body}"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

username="$(echo "${body}" | python3 -c "import json,sys; print(json.load(sys.stdin)['username'])")"
role_exists "${username}" && pass "role ${username} exists before pg stop" \
  || fail "role ${username} missing before pg stop"

pass "stopping Postgres container ${PG_CONTAINER}"
docker stop "${PG_CONTAINER}" >/dev/null

wait_secs=$(( LEASE_TTL + REAPER_INTERVAL + 10 ))
pass "waiting ${wait_secs}s for lease expiry while Postgres is down"
sleep "${wait_secs}"

role_exists "${username}" \
  && pass "role still present while Postgres down (expected until reaper succeeds)" \
  || pass "role already absent (reaper may have retried)"

pass "restarting Postgres container ${PG_CONTAINER}"
docker start "${PG_CONTAINER}" >/dev/null

ready=false
for _ in $(seq 1 30); do
  if docker exec "${PG_CONTAINER}" pg_isready -U sbadmin -d strongbox >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
${ready} && pass "Postgres is ready again" || fail "Postgres did not become ready in time"

# Allow reaper exponential backoff retries (10s initial + margin).
retry_wait=45
pass "waiting ${retry_wait}s for revocation_pending retry after Postgres recovery"
sleep "${retry_wait}"

if role_exists "${username}"; then
  fail "role ${username} still present after TTL + Postgres recovery — cleanup failed"
else
  pass "role ${username} removed automatically after lease expiry"
fi

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
