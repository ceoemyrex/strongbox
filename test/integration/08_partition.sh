#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 08_partition: 2-1 split, minority refuses writes, majority continues"

[[ -n "${ROOT_TOKEN}" ]] || { fail "STRONGBOX_ROOT_TOKEN required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

docker network disconnect strongbox_cluster strongbox-node-3 2>/dev/null || true
pass "isolated node-3 from cluster"

sleep 3

code="$(curl -sk -o /dev/null -w "%{http_code}" \
  -X PUT "${BASE_URL}/v1/secrets/app/partition-test" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"partition":"majority"}}')"
[[ "${code}" == "201" || "${code}" == "200" ]] \
  && pass "majority serves writes (${code})" \
  || fail "majority write returned ${code}"

code="$(curl -sk -o /tmp/sb_minority.json -w "%{http_code}" \
  -X PUT "http://localhost:8203/v1/secrets/app/partition-test" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"partition":"minority"}}')"
[[ "${code}" == "503" ]] \
  && pass "minority refuses writes (503)" \
  || fail "minority write returned ${code} (expected 503)"

docker network connect strongbox_cluster strongbox-node-3 2>/dev/null || true
pass "reconnected node-3 to cluster"

sleep 3

code="$(curl -sk -o /dev/null -w "%{http_code}" "http://localhost:8203/v1/sys/health")"
[[ "${code}" == "200" ]] && pass "node-3 healthy after rejoin" || fail "node-3 not healthy (${code})"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
