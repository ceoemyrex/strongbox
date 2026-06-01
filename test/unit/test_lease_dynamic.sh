#!/usr/bin/env bash
# test/unit/test_lease_dynamic.sh — offline tests for Trojan's lease + dynamic modules
# Run: bash test/unit/test_lease_dynamic.sh
# Requires: postgres reachable at STRONGBOX_PG_DSN (or skip dynamic tests)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LIB="${ROOT}/lib"

PASS=0; FAIL=0
pass() { echo "  PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "  FAIL: $*"; FAIL=$(( FAIL + 1 )); }

source "${LIB}/lease.sh"
source "${LIB}/dynamic.sh"

echo "==> lease lifecycle (in-memory)"

lease_create "secret/test/key" 30
id="${_LEASE_LAST_ID}"
[[ -n "${id}" ]] && pass "lease_create returned id" || fail "lease_create failed"

meta="$(lease_get "${id}")"
echo "${meta}" | grep -q '"state":"active"' \
  && pass "new lease is active" || fail "expected active state in ${meta}"

renew="$(lease_renew "${id}")"
echo "${renew}" | grep -q '"new_ttl"' \
  && pass "lease_renew returned new_ttl" || fail "renew failed: ${renew}"

# Force expiry by backdating expires_at in metadata.
_LEASES["${id}"]="$(echo "${_LEASES[${id}]}" \
  | sed 's/"expires_at":[0-9]*/"expires_at":1/')"
_lease_reaper_tick

state="${_LEASE_STATE[${id}]}"
[[ "${state}" == "revoked" || "${state}" == "revocation_pending" ]] \
  && pass "reaper expired lease → ${state}" \
  || fail "expected revoked/revocation_pending after expiry, got ${state}"

echo ""
echo "==> dynamic postgres (needs STRONGBOX_PG_DSN)"

export STRONGBOX_PG_DSN="${STRONGBOX_PG_DSN:-postgresql://sbadmin:strongbox@localhost:5432/strongbox}"
export DYNAMIC_LEASE_TTL="${DYNAMIC_LEASE_TTL:-30}"

if PGPASSWORD="" psql "${STRONGBOX_PG_DSN}" -c "SELECT 1" >/dev/null 2>&1; then
  resp="$(dynamic_postgres_read "readonly")"
  user="$(echo "${resp}" | python3 -c "import json,sys; print(json.load(sys.stdin)['username'])")"
  lid="$(echo "${resp}" | python3 -c "import json,sys; print(json.load(sys.stdin)['lease']['lease_id'])")"

  [[ "${user}" == sb_* ]] && pass "dynamic_postgres_read minted ${user}" \
    || fail "bad username: ${user}"

  psql "${STRONGBOX_PG_DSN}" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${user}'" | grep -q 1 \
    && pass "role exists in pg_roles" || fail "role missing in pg_roles"

  dynamic_revoke_lease "${lid}" \
    && pass "dynamic_revoke_lease succeeded" || fail "revoke failed"

  psql "${STRONGBOX_PG_DSN}" -tAc "SELECT 1 FROM pg_roles WHERE rolname='${user}'" | grep -qv 1 \
    && pass "role dropped after revoke" || fail "role still present after revoke"
else
  echo "  SKIP: Postgres not reachable at ${STRONGBOX_PG_DSN}"
fi

echo ""
echo "${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
