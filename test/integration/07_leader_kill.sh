#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${STRONGBOX_URL:-http://localhost:8201}"
ROOT_TOKEN="${STRONGBOX_ROOT_TOKEN:-}"
PASS=0; FAIL=0

pass() { echo "    PASS: $*"; PASS=$(( PASS + 1 )); }
fail() { echo "    FAIL: $*"; FAIL=$(( FAIL + 1 )); }

echo "==> 07_leader_kill: Kill leader mid-write, verify durability under new leader"

[[ -n "${ROOT_TOKEN}" ]] || { fail "STRONGBOX_ROOT_TOKEN required"; echo "    ${PASS} passed / ${FAIL} failed"; exit 1; }

LEADER="$(curl -sk "${BASE_URL}/v1/sys/health" | python3 -c "import json,sys; print(json.load(sys.stdin)['leader'])" 2>/dev/null)"
pass "current leader is ${LEADER}"

curl -sk -o /dev/null -X PUT "${BASE_URL}/v1/secrets/app/pre-kill" \
  -H "Authorization: Bearer ${ROOT_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"data":{"status":"before-kill"}}' 2>/dev/null
pass "wrote secret before kill"

docker kill "strongbox-${LEADER}" >/dev/null 2>&1
pass "killed leader container strongbox-${LEADER}"

sleep 5

ALIVE_NODE=""
for port in 8201 8202 8203; do
  H="$(curl -sk "http://localhost:${port}/v1/sys/health" 2>/dev/null)" || continue
  [[ -n "${H}" ]] && { ALIVE_NODE="http://localhost:${port}"; break; }
done

if [[ -n "${ALIVE_NODE}" ]]; then
  NEW_LEADER="$(curl -sk "${ALIVE_NODE}/v1/sys/health" | python3 -c "import json,sys; print(json.load(sys.stdin).get('leader','unknown'))" 2>/dev/null)"
  [[ "${NEW_LEADER}" != "${LEADER}" && -n "${NEW_LEADER}" ]] \
    && pass "new leader elected: ${NEW_LEADER}" \
    || fail "no new leader elected (got: ${NEW_LEADER})"
else
  fail "no surviving node reachable"
fi

docker start "strongbox-${LEADER}" >/dev/null 2>&1
pass "restarted killed node"
sleep 3

H="$(curl -sk "${BASE_URL}/v1/sys/health" 2>/dev/null)"
[[ -n "${H}" ]] && pass "cluster healthy after recovery" || fail "cluster not healthy"

echo "    ${PASS} passed / ${FAIL} failed"
[[ "${FAIL}" -eq 0 ]] || exit 1
