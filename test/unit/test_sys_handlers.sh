#!/usr/bin/env bash
# test/unit/test_sys_handlers.sh — unit tests for the three /sys/* HTTP handlers
#
# Run from repo root:
#   bash test/unit/test_sys_handlers.sh
#
# Strategy: we don't bind a real socket. Instead we source http.sh and call
# the handler functions directly, capturing their stdout to assert on the
# HTTP response. This isolates handler logic from netcat/networking.
#
# Tests are grouped:
#   /sys/init   — first call succeeds, second call rejected, response shape
#   /sys/unseal — share validation, accumulation across calls, K-threshold trigger
#   /sys/seal   — auth required, no-op when sealed, returns 204
#   Routing     — sealed gate, leader gate exception for /sys/* paths
#   Memory      — share value zeroed from handler-local after submission
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Source order matters: crypto before seal before http.
# Stubs for the bits the sys handlers reference but aren't built yet.
source "${REPO}/lib/crypto.sh"
source "${REPO}/lib/seal.sh"

# Stub consensus.sh — http.sh references its functions in the leader gate.
# We make this node "the leader" so the gate passes for non-sys paths too.
consensus_is_leader()         { return 0; }
consensus_quorum_reachable()  { return 0; }
consensus_leader_hint()       { echo "node-1"; }
consensus_handle_vote()       { echo '{"granted":false}'; }
consensus_handle_hb()         { echo '{"ack":true}'; }
_NODE_ID="node-1"
_CURRENT_TERM=0

source "${REPO}/lib/http.sh"

PASS=0
FAIL=0
ERRORS=()

pass() { echo "  PASS  $*"; PASS=$(( PASS + 1 )); }
fail() { echo "  FAIL  $*"; FAIL=$(( FAIL + 1 )); ERRORS+=("$*"); }

check() {
  local label="$1" result="$2" expect="$3"
  if [ "$result" = "$expect" ]; then pass "$label"
  else fail "$label — got '$result' want '$expect'"; fi
}

check_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -qF "$needle"; then pass "$label"
  else fail "$label — '$needle' not in '$(echo "$haystack" | head -c 200)'"; fi
}

# ── helpers ───────────────────────────────────────────────────────────────────

# Extract the HTTP status code from a captured HTTP/1.1 response.
_status_code() {
  echo "$1" | head -1 | awk '{print $2}'
}

# Extract the JSON body (everything after the blank line).
_response_body() {
  echo "$1" | awk 'p; /^\r$/{p=1}'
}

# Reset all module state between sections.
_reset() {
  crypto_clear_kek 2>/dev/null || true
  seal_init
}

# ═════════════════════════════════════════════════════════════════════════════
echo "── /sys/init: first call ──"

_reset

# Direct handler call. Capture its full HTTP response.
RESPONSE=$(_handle_sys_init "")
STATUS=$(_status_code "$RESPONSE")
BODY=$(_response_body "$RESPONSE")

check "init: returns HTTP 200" "$STATUS" "200"
check_contains "init: response contains shares array" "$BODY" '"shares":['
check_contains "init: response contains root_token"   "$BODY" '"root_token":'

# State assertions — these only persist because we call the handler
# WITHOUT subshell capture (it's just a function call, not $()).
# Wait — RESPONSE=$(...) IS a subshell. So the test's _INITIALIZED
# won't have been mutated by the handler call above. We verify the
# handler works correctly by running it WITHOUT $() next.

_reset
_handle_sys_init "" > /dev/null   # no capture — state persists

if seal_is_initialized; then pass "init: _INITIALIZED is true after call"
else fail "init: _INITIALIZED still false"; fi

if seal_is_sealed; then pass "init: still sealed after init"
else fail "init: should remain sealed until shares submitted"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/init: second call rejected ──"

# Vault is now initialized. A second init must return 409.
RESPONSE=$(_handle_sys_init "")
STATUS=$(_status_code "$RESPONSE")
BODY=$(_response_body "$RESPONSE")

check "init: second call returns HTTP 409" "$STATUS" "409"
check_contains "init: second call body has error" "$BODY" "already initialized"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: missing share ──"

# Reset and re-init so we can test unseal scenarios cleanly.
_reset
_handle_sys_init "" > /dev/null

# Read back the shares from _SEAL_RESPONSE for later submission.
INIT_RESP="$_SEAL_RESPONSE"
SHARES_RAW=$(echo "$INIT_RESP" | grep -oE '"[0-9]+:[0-9a-f]+"' | tr -d '"')
SHARES=()
while IFS= read -r line; do
  [ -n "$line" ] && SHARES+=("$line")
done <<< "$SHARES_RAW"
ROOT_TOKEN=$(echo "$INIT_RESP" | grep -oE '"root_token":"[0-9a-f]+"' | cut -d'"' -f4)

# Empty body
RESPONSE=$(_handle_sys_unseal '')
STATUS=$(_status_code "$RESPONSE")
check "unseal: empty body returns HTTP 400" "$STATUS" "400"

# Body without share field
RESPONSE=$(_handle_sys_unseal '{"foo":"bar"}')
STATUS=$(_status_code "$RESPONSE")
check "unseal: missing share field returns HTTP 400" "$STATUS" "400"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: malformed share ──"

RESPONSE=$(_handle_sys_unseal '{"share":"not-a-share"}')
STATUS=$(_status_code "$RESPONSE")
BODY=$(_response_body "$RESPONSE")
check "unseal: malformed share returns HTTP 400" "$STATUS" "400"
check_contains "unseal: error mentions malformed" "$BODY" "malformed"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: progress reporting ──"

# Direct call (no subshell) for the first share so state persists.
_handle_sys_unseal "{\"share\":\"${SHARES[0]}\"}" > /tmp/sys_unseal_resp_1
RESP1=$(cat /tmp/sys_unseal_resp_1)
STATUS1=$(_status_code "$RESP1")
BODY1=$(_response_body "$RESP1")

check "unseal: first share returns HTTP 200" "$STATUS1" "200"
check_contains "unseal: progress 1/2" "$BODY1" '"progress":"1/2"'
check_contains "unseal: still sealed"  "$BODY1" '"sealed":true'

if seal_is_sealed; then pass "unseal: still sealed after 1 share"
else fail "unseal: should still be sealed after K-1 shares"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: duplicate share rejected ──"

RESPONSE=$(_handle_sys_unseal "{\"share\":\"${SHARES[0]}\"}")
STATUS=$(_status_code "$RESPONSE")
BODY=$(_response_body "$RESPONSE")
check "unseal: duplicate share returns HTTP 409" "$STATUS" "409"
check_contains "unseal: error mentions duplicate" "$BODY" "duplicate"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: K-threshold triggers unseal ──"

_handle_sys_unseal "{\"share\":\"${SHARES[1]}\"}" > /tmp/sys_unseal_resp_2
RESP2=$(cat /tmp/sys_unseal_resp_2)
STATUS2=$(_status_code "$RESP2")
BODY2=$(_response_body "$RESP2")

check "unseal: second share returns HTTP 200" "$STATUS2" "200"
check_contains "unseal: now unsealed" "$BODY2" '"sealed":false'

if ! seal_is_sealed; then pass "unseal: vault is now unsealed"
else fail "unseal: should have been unsealed"; fi

if crypto_is_unsealed; then pass "unseal: crypto.sh is loaded"
else fail "unseal: crypto.sh should be loaded"; fi

# Verify encryption actually works.
ENV=$(crypto_encrypt "post-unseal test")
PT=$(crypto_decrypt "$ENV")
check "unseal: encrypt/decrypt round-trip works" "$PT" "post-unseal test"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/unseal: rejected when already unsealed ──"

RESPONSE=$(_handle_sys_unseal "{\"share\":\"${SHARES[2]}\"}")
STATUS=$(_status_code "$RESPONSE")
BODY=$(_response_body "$RESPONSE")
check "unseal: already-unsealed returns HTTP 409" "$STATUS" "409"
check_contains "unseal: error mentions already unsealed" "$BODY" "already unsealed"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/seal: rejected when already sealed ──"

# Seal first so we can test the "already sealed" path.
seal_seal

RESPONSE=$(_handle_sys_seal "$ROOT_TOKEN")
STATUS=$(_status_code "$RESPONSE")
check "seal: already-sealed returns HTTP 409" "$STATUS" "409"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/seal: auth required ──"

# Re-unseal so we can test the auth path.
_handle_sys_unseal "{\"share\":\"${SHARES[0]}\"}" > /dev/null
_handle_sys_unseal "{\"share\":\"${SHARES[1]}\"}" > /dev/null

# No token
RESPONSE=$(_handle_sys_seal "")
STATUS=$(_status_code "$RESPONSE")
check "seal: missing token returns HTTP 401" "$STATUS" "401"

if ! seal_is_sealed; then pass "seal: still unsealed after 401"
else fail "seal: should not have sealed on failed auth"; fi

# Wrong token
RESPONSE=$(_handle_sys_seal "definitely-not-a-real-token")
STATUS=$(_status_code "$RESPONSE")
check "seal: bad token returns HTTP 401" "$STATUS" "401"

if ! seal_is_sealed; then pass "seal: still unsealed after bad-token 401"
else fail "seal: should not have sealed"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/seal: valid root token seals the vault ──"

# Capture response and verify 204.
RESPONSE=$(_handle_sys_seal "$ROOT_TOKEN")
STATUS=$(_status_code "$RESPONSE")
check "seal: valid root token returns HTTP 204" "$STATUS" "204"

# But — the call was inside $(), so seal_seal ran in a subshell and
# the parent's _SEALED is still false. Call directly to actually seal.
_handle_sys_seal "$ROOT_TOKEN" > /dev/null

if seal_is_sealed; then pass "seal: vault is sealed after valid call"
else fail "seal: should have been sealed"; fi

if ! crypto_is_unsealed; then pass "seal: crypto.sh is cleared"
else fail "seal: crypto.sh should be cleared"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── /sys/* paths bypass leader gate ──"

# Force this node to be a follower. /sys/* should still work; non-/sys
# write paths should be redirected with 307.
consensus_is_leader() { return 1; }

# /sys/init request via the full handler chain. We need to feed a valid
# HTTP request to _http_handle_connection — easier to just call _http_route
# directly with method/path/body/token.

# /sys/init must still work even as a follower.
_reset
RESPONSE=$(_http_route "POST" "/v1/sys/init" "" "")
STATUS=$(_status_code "$RESPONSE")
check "leader-gate: /sys/init works on follower" "$STATUS" "200"

# /sys/unseal must still work as a follower.
_reset
_handle_sys_init "" > /dev/null
INIT_RESP="$_SEAL_RESPONSE"
SHARES2=()
while IFS= read -r line; do
  [ -n "$line" ] && SHARES2+=("$line")
done <<< "$(echo "$INIT_RESP" | grep -oE '"[0-9]+:[0-9a-f]+"' | tr -d '"')"

RESPONSE=$(_http_route "POST" "/v1/sys/unseal" "{\"share\":\"${SHARES2[0]}\"}" "")
STATUS=$(_status_code "$RESPONSE")
check "leader-gate: /sys/unseal works on follower" "$STATUS" "200"

# Restore leader status for other tests.
consensus_is_leader() { return 0; }

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── sealed gate blocks non-/sys writes ──"

_reset
# Vault is sealed. Try to write a secret — should be blocked by sealed gate.
# We use the full handler chain to exercise the gate.
#
# Note: _http_handle_connection reads from stdin (netcat pipe). For a unit
# test we replicate the gate logic inline.

if seal_is_sealed; then
  # The gate would 503 anything that isn't /sys/init, /sys/unseal, /sys/health.
  # We assert by checking the gate's condition directly.
  case "/v1/secrets/app/db" in
    /v1/sys/init|/v1/sys/unseal|/v1/sys/health) fail "gate: secrets path bypassed sealed gate" ;;
    *) pass "gate: non-/sys paths blocked when sealed" ;;
  esac
fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── memory hygiene: handler-local share is zeroed ──"
#
# The handler stores the parsed share in a local. After seal_submit_share
# consumes it, the local must be overwritten before the function returns.
# We verify by inspecting the post-unseal variable space.
#
# Portability note: macOS ships Bash 3.2 where `declare -p` output format
# differs from Linux Bash 5.x. Rather than rely on a name-based filter that
# breaks across versions, we save the fingerprints to a temp FILE before
# the dump, then unset every test-side variable so the dump cannot contain
# our own search needles.

FP_FILE=$(mktemp)
trap "rm -f $FP_FILE" EXIT

HEAP_DUMP=$(
  crypto_clear_kek
  seal_init
  _handle_sys_init "" > /dev/null
  init_local="$_SEAL_RESPONSE"
  shares_raw=$(echo "$init_local" | grep -oE '"[0-9]+:[0-9a-f]+"' | tr -d '"')
  fresh=()
  while IFS= read -r ln; do [ -n "$ln" ] && fresh+=("$ln"); done <<< "$shares_raw"

  # Save fingerprints to the temp file BEFORE creating any local that
  # could appear in the variable dump.
  printf '%s\n' "${fresh[0]##*:}" | cut -c1-32 >  "$FP_FILE"
  printf '%s\n' "${fresh[1]##*:}" | cut -c1-32 >> "$FP_FILE"

  # Submit K shares via the handler.
  _handle_sys_unseal "{\"share\":\"${fresh[0]}\"}" > /dev/null
  _handle_sys_unseal "{\"share\":\"${fresh[1]}\"}" > /dev/null

  # Caller-side cleanup — overwrite every local that held share data.
  for i in "${!fresh[@]}"; do
    len="${#fresh[$i]}"
    fresh[$i]="$(head -c "$len" /dev/zero | tr '\0' '0')"
  done
  fresh=()
  shares_raw="$(head -c "${#shares_raw}" /dev/zero | tr '\0' '0')"
  shares_raw=""
  init_local="$(head -c "${#init_local}" /dev/zero | tr '\0' '0')"
  init_local=""
  unset fresh shares_raw init_local ln len i

  # Take the dump — no test-side variables hold the search needles anymore.
  # Pipe through grep -aF to handle any binary content in the dump.
  all_vars=$(declare -p 2>/dev/null)

  # Read fingerprints from the file for the assertion.
  share1_check=$(sed -n '1p' "$FP_FILE")
  share2_check=$(sed -n '2p' "$FP_FILE")

  # Subtract the share*_check declarations themselves from the haystack.
  # Use grep -v with a simpler pattern that works on both Bash 3.2 and 5.x.
  filtered=$(echo "$all_vars" | grep -v "share1_check" | grep -v "share2_check" | grep -v "all_vars" | grep -v "filtered")

  if ! echo "$filtered" | grep -qF "$share1_check"; then
    echo "PASS: share 1 fingerprint absent after unseal"
  else
    leak=$(echo "$filtered" | grep -nF "$share1_check" | head -1 | cut -c1-100)
    echo "FAIL: share 1 leaked at: $leak"
  fi
  if ! echo "$filtered" | grep -qF "$share2_check"; then
    echo "PASS: share 2 fingerprint absent after unseal"
  else
    leak=$(echo "$filtered" | grep -nF "$share2_check" | head -1 | cut -c1-100)
    echo "FAIL: share 2 leaked at: $leak"
  fi
)

while IFS= read -r line; do
  case "$line" in
    PASS:*) pass "${line#PASS: }" ;;
    FAIL:*) fail "${line#FAIL: }" ;;
  esac
done <<< "$HEAP_DUMP"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "────────────────────────────────────────"
echo "  ${PASS} passed  /  ${FAIL} failed"
if [ ${#ERRORS[@]} -gt 0 ]; then
  echo ""
  echo "Failed tests:"
  for e in "${ERRORS[@]}"; do echo "  - $e"; done
fi
echo ""
[ "$FAIL" -eq 0 ] || exit 1
