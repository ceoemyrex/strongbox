#!/usr/bin/env bash
# test/unit/test_seal.sh — unit tests for lib/seal.sh
#
# Run from repo root:
#   bash test/unit/test_seal.sh
#
# Tests are grouped:
#   Boot state         — sealed, uninitialized on fresh load
#   Config parsing     — K and N loaded from config.yaml
#   Cluster init       — generates KEK, returns shares + root token, idempotent
#   Share submission   — validation, accumulation, K threshold, duplicates
#   Reconstruction     — bundle assembly, crypto.sh integration, error paths
#   Memory hygiene     — shares and bundle zeroed after unseal
#   Re-seal            — clears KEK but preserves initialized state
#   Round-trip         — full init → unseal → seal → unseal cycle
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# We must source crypto.sh BEFORE seal.sh — seal.sh calls crypto_set_kek etc.
source "${REPO}/lib/crypto.sh"
source "${REPO}/lib/seal.sh"

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
  else fail "$label — '$needle' not found"; fi
}

# Reset module state between test sections.
_reset() {
  crypto_clear_kek 2>/dev/null || true
  seal_init
}

# ═════════════════════════════════════════════════════════════════════════════
echo "── boot state ──"

_reset

if seal_is_sealed; then pass "boot: vault is sealed"
else fail "boot: vault should be sealed"; fi

if ! seal_is_initialized; then pass "boot: vault is uninitialized"
else fail "boot: vault should be uninitialized"; fi

if ! crypto_is_unsealed; then pass "boot: crypto.sh reports sealed"
else fail "boot: crypto.sh should report sealed"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── config parsing ──"

# Verify K and N were loaded from config.yaml
STATUS=$(seal_status)
check_contains "config: threshold present in status" "$STATUS" '"threshold":'
check_contains "config: shares present in status"    "$STATUS" '"shares":'

# Default config has K=2, N=3
check_contains "config: K=2 from config.yaml" "$STATUS" '"threshold":2'
check_contains "config: N=3 from config.yaml" "$STATUS" '"shares":3'

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── cluster init ──"

_reset

seal_init_cluster || true
INIT_RESPONSE="$_SEAL_RESPONSE"
check_contains "init: response contains shares array" "$INIT_RESPONSE" '"shares":['
check_contains "init: response contains root_token"  "$INIT_RESPONSE" '"root_token":'

# After init: still sealed, but now initialized.
if seal_is_sealed; then pass "post-init: still sealed"
else fail "post-init: should remain sealed until shares submitted"; fi

if seal_is_initialized; then pass "post-init: marked initialized"
else fail "post-init: should be marked initialized"; fi

# Crypto layer must NOT be loaded after init — only after unseal.
if ! crypto_is_unsealed; then pass "post-init: crypto.sh still sealed"
else fail "post-init: crypto.sh should not be loaded yet"; fi

# Extract shares from response. Format: "x:hexbytes"
SHARES_RAW=$(echo "$INIT_RESPONSE" \
  | grep -oE '"[0-9]+:[0-9a-f]+"' \
  | tr -d '"')
SHARE_COUNT=$(echo "$SHARES_RAW" | wc -l | tr -d ' ')
check "init: exactly N=3 shares returned" "$SHARE_COUNT" "3"

# Each share should be 64 hex chars after the x: (32-byte bundle? no, 64 bytes)
# Actually: bundle is 128 hex chars = 64 bytes, so each share's y_bytes is 64 bytes = 128 hex
SHARE1=$(echo "$SHARES_RAW" | sed -n '1p')
SHARE_HEX=$(echo "$SHARE1" | cut -d: -f2)
check "init: share y_bytes is 128 hex chars (64 bytes)" "${#SHARE_HEX}" "128"

# Root token: 32 bytes hex = 64 chars
ROOT_TOKEN=$(echo "$INIT_RESPONSE" | grep -oE '"root_token":"[0-9a-f]+"' | cut -d'"' -f4)
check "init: root_token is 64 hex chars" "${#ROOT_TOKEN}" "64"

# Idempotency: a second init must fail.
seal_init_cluster 2>&1 || true
INIT_AGAIN="$_SEAL_RESPONSE"
check_contains "init: second call rejected" "$INIT_AGAIN" "already initialized"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── share submission ──"

# Save shares from the successful init for later tests.
SAVED_SHARES=()
while IFS= read -r line; do
  [ -n "$line" ] && SAVED_SHARES+=("$line")
done <<< "$SHARES_RAW"

# Malformed share rejected
seal_submit_share "not-a-share" 2>&1 || true
ERR="$_SEAL_RESPONSE"
check_contains "submit: malformed share rejected" "$ERR" "malformed share"

# Empty share rejected
seal_submit_share "" 2>&1 || true
ERR="$_SEAL_RESPONSE"
check_contains "submit: empty share rejected" "$ERR" "malformed share"

# Wrong format (no colon)
seal_submit_share "1abcdef" 2>&1 || true
ERR="$_SEAL_RESPONSE"
check_contains "submit: missing colon rejected" "$ERR" "malformed share"

# Submit first share — should show progress 1/2
seal_submit_share "${SAVED_SHARES[0]}" || true
RESP="$_SEAL_RESPONSE"
check_contains "submit: first share shows progress 1/2" "$RESP" '"progress":"1/2"'
check_contains "submit: still sealed after 1 share"     "$RESP" '"sealed":true'

# Duplicate share rejected
seal_submit_share "${SAVED_SHARES[0]}" 2>&1 || true
DUP="$_SEAL_RESPONSE"
check_contains "submit: duplicate share rejected" "$DUP" "duplicate share"

# Progress shouldn't advance from duplicate
STATUS=$(seal_status)
check_contains "submit: duplicate did not advance progress" "$STATUS" '"progress":"1/2"'

# Submit second share — should unseal
seal_submit_share "${SAVED_SHARES[1]}" || true
RESP="$_SEAL_RESPONSE"
check_contains "submit: second share triggers unseal" "$RESP" '"sealed":false'

if ! seal_is_sealed; then pass "post-unseal: vault is unsealed"
else fail "post-unseal: vault should be unsealed"; fi

if crypto_is_unsealed; then pass "post-unseal: crypto.sh is loaded"
else fail "post-unseal: crypto.sh should be loaded"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── post-unseal sanity: encrypt/decrypt works ──"

# The whole point of unseal: crypto.sh should now work.
ENV=$(crypto_encrypt "post-unseal secret")
RECOVERED=$(crypto_decrypt "$ENV")
check "post-unseal: encrypt/decrypt roundtrip" "$RECOVERED" "post-unseal secret"

# Submit additional share after already unsealed — must be rejected
seal_submit_share "${SAVED_SHARES[2]}" 2>&1 || true
ERR="$_SEAL_RESPONSE"
check_contains "submit: rejected when already unsealed" "$ERR" "already unsealed"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── re-seal ──"

seal_seal

if seal_is_sealed; then pass "re-seal: vault is sealed"
else fail "re-seal: vault should be sealed"; fi

if ! crypto_is_unsealed; then pass "re-seal: crypto.sh cleared"
else fail "re-seal: crypto.sh should be cleared"; fi

# But init state must persist — we shouldn't have to re-init.
if seal_is_initialized; then pass "re-seal: initialized state preserved"
else fail "re-seal: should remain initialized"; fi

# Encrypt should now fail
ERR=$(crypto_encrypt "should fail" 2>&1) && fail "re-seal: encrypt should be blocked" \
  || pass "re-seal: encrypt is blocked"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── re-unseal cycle (different share combination) ──"

# Use shares 0 and 2 this time — different combination, same secret.
seal_submit_share "${SAVED_SHARES[0]}" || true
RESP="$_SEAL_RESPONSE"
check_contains "re-unseal: first share accepted" "$RESP" '"progress":"1/2"'

seal_submit_share "${SAVED_SHARES[2]}" || true
RESP="$_SEAL_RESPONSE"
check_contains "re-unseal: second share unsealed with different combo" "$RESP" '"sealed":false'

# Now encrypt with the NEW KEK loaded.
# It must be the SAME KEK as before — try to decrypt the original envelope.
RECOVERED=$(crypto_decrypt "$ENV")
check "re-unseal: same KEK reconstructed (old envelope decrypts)" "$RECOVERED" "post-unseal secret"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── threshold below K cannot reconstruct ──"

seal_seal
_reset
seal_init_cluster

# Reload the new shares (a new init was just called)
NEW_INIT=$(seal_init 2>&1; seal_init_cluster)
# Wait: seal_init was already called in _reset, then seal_init_cluster generates fresh shares
# Let's just submit only 1 share and verify it does NOT reconstruct.

# Re-do properly:
_reset
seal_init_cluster
INIT_NEW="$_SEAL_RESPONSE"
SHARES_NEW=$(echo "$INIT_NEW" | grep -oE '"[0-9]+:[0-9a-f]+"' | tr -d '"')
NEW_SHARES=()
while IFS= read -r line; do
  [ -n "$line" ] && NEW_SHARES+=("$line")
done <<< "$SHARES_NEW"

# Submit only K-1 = 1 share
seal_submit_share "${NEW_SHARES[0]}"

if seal_is_sealed; then pass "threshold: still sealed with K-1 shares"
else fail "threshold: should be sealed with K-1 shares"; fi

if ! crypto_is_unsealed; then pass "threshold: crypto.sh not loaded with K-1"
else fail "threshold: crypto.sh should not be loaded"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── memory hygiene (the heap-dump test) ──"
#
# WHAT WE CAN VERIFY HERE:
#   This test runs in the same Bash process as seal.sh. Any variable WE
#   create to feed shares into seal_submit_share will of course still exist
#   until we explicitly zero it — that is a TEST artefact, not a real leak.
#
#   The real-world equivalent is the HTTP handler in http.sh: it parses
#   the request body into a local variable, calls seal_submit_share, then
#   must overwrite that local. The handler owns the cleanup of its own
#   inputs. We model that pattern explicitly below.
#
# SEARCH-VALUE TRICK:
#   We cannot store the share hex as the search needle — that variable
#   itself becomes a fresh leak. Instead we compute a SHA-256 of each
#   sensitive value and search for the value, NOT the hash. The hash
#   lets us recognise a hit without holding the secret. Throughout the
#   memory dump we look for the share hex substring; the only variable
#   that contains it must be the dump itself (transient).

# Run the entire memory-sensitive section inside a subshell so the test
# script's outer variables don't pollute the dump. Subshell state changes
# (including the unseal) do not propagate to the parent — that is fine
# because we only care about the in-subshell snapshot.
HEAP_DUMP_RESULTS=$(
  # ─── 1. fresh init in this subshell ────────────────────────────────────
  seal_init
  seal_init_cluster
  local_init="$_SEAL_RESPONSE"
  shares_raw=$(echo "$local_init" | grep -oE '"[0-9]+:[0-9a-f]+"' | tr -d '"')

  fresh=()
  while IFS= read -r line; do
    [ -n "$line" ] && fresh+=("$line")
  done <<< "$shares_raw"

  # Capture the FIRST 32 HEX CHARS of each share's y-bytes as the search
  # "fingerprint". 32 chars is unique enough to detect a leak while small
  # enough that it's still likely-unique in the dump output (the hashes of
  # short strings collide with random hex too often).
  share1_fp="${fresh[0]##*:}"
  share1_fp="${share1_fp:0:32}"
  share2_fp="${fresh[1]##*:}"
  share2_fp="${share2_fp:0:32}"

  # ─── 2. submit shares — vault unseals ──────────────────────────────────
  seal_submit_share "${fresh[0]}"
  seal_submit_share "${fresh[1]}"

  # ─── 3. caller-side cleanup (this is what http.sh must also do) ────────
  for i in "${!fresh[@]}"; do
    len="${#fresh[$i]}"
    fresh[$i]="$(head -c "$len" /dev/zero | tr '\0' '0')"
  done
  fresh=()
  shares_raw="$(head -c "${#shares_raw}" /dev/zero | tr '\0' '0')"
  shares_raw=""
  local_init="$(head -c "${#local_init}" /dev/zero | tr '\0' '0')"
  local_init=""

  # ─── 4. snapshot all variables ─────────────────────────────────────────
  all_vars=$(declare -p 2>/dev/null | grep -v '^declare -[fF]')

  # The dump itself contains share1_fp and share2_fp (we still need them
  # for searching). Strip those declarations before counting leaks.
  filtered=$(echo "$all_vars" \
    | grep -vE '^declare -- (share[12]_fp|all_vars|filtered|kek_count|hmac_count)=')

  # ─── 5. assertion: _SHARES_COLLECTED is empty ─────────────────────────
  if [ "${#_SHARES_COLLECTED[@]}" -eq 0 ]; then
    echo "PASS: _SHARES_COLLECTED is empty"
  else
    echo "FAIL: _SHARES_COLLECTED has ${#_SHARES_COLLECTED[@]} entries"
  fi

  # ─── 6. assertion: share fingerprints absent from filtered dump ───────
  if ! echo "$filtered" | grep -qF "$share1_fp"; then
    echo "PASS: share 1 hex absent from process memory"
  else
    leak=$(echo "$filtered" | grep -nF "$share1_fp" | head -1 | cut -c1-100)
    echo "FAIL: share 1 hex leaked at: $leak"
  fi
  if ! echo "$filtered" | grep -qF "$share2_fp"; then
    echo "PASS: share 2 hex absent from process memory"
  else
    echo "FAIL: share 2 hex leaked"
  fi

  # ─── 7. assertion: KEK appears in exactly one variable each ───────────
  kek_count=$(echo "$filtered" | grep -cF "$_STRONGBOX_KEK" || true)
  hmac_count=$(echo "$filtered" | grep -cF "$_STRONGBOX_HMAC_KEK" || true)
  [ "$kek_count" -eq 1 ]  && echo "PASS: KEK in exactly 1 variable"  || echo "FAIL: KEK in $kek_count variables"
  [ "$hmac_count" -eq 1 ] && echo "PASS: HMAC in exactly 1 variable" || echo "FAIL: HMAC in $hmac_count variables"

  # ─── 8. seal and re-snapshot — KEK pair must be gone ──────────────────
  # Save the KEK fingerprints (first 32 chars) so we can search after seal.
  kek_fp="${_STRONGBOX_KEK:0:32}"
  hmac_fp="${_STRONGBOX_HMAC_KEK:0:32}"

  seal_seal

  all_vars_after=$(declare -p 2>/dev/null | grep -v '^declare -[fF]')
  filtered_after=$(echo "$all_vars_after" \
    | grep -vE '^declare -- (kek_fp|hmac_fp|share[12]_fp|all_vars|all_vars_after|filtered|filtered_after|kek_count|hmac_count)=')

  if ! echo "$filtered_after" | grep -qF "$kek_fp"; then
    echo "PASS: KEK absent after seal"
  else
    echo "FAIL: KEK still present after seal"
  fi
  if ! echo "$filtered_after" | grep -qF "$hmac_fp"; then
    echo "PASS: HMAC absent after seal"
  else
    echo "FAIL: HMAC still present after seal"
  fi
)

# Replay the subshell's results into the harness counters.
while IFS= read -r line; do
  case "$line" in
    PASS:*) pass "memory: ${line#PASS: }" ;;
    FAIL:*) fail "memory: ${line#FAIL: }" ;;
  esac
done <<< "$HEAP_DUMP_RESULTS"

# Subshell mutations did not propagate; the parent still has the prior
# unseal state. Re-seal so subsequent test sections start clean.
seal_seal

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── error paths ──"

_reset

# Submitting a share before init
seal_submit_share "1:abcdef" 2>&1 || true
ERR="$_SEAL_RESPONSE"
check_contains "error: submit before init rejected" "$ERR" "not initialized"

# Init, then submit garbage share that passes regex but fails reconstruction
seal_init_cluster
# A share with wrong x value or corrupted y bytes
GARBAGE_SHARE="9:$(openssl rand -hex 64)"
seal_submit_share "$GARBAGE_SHARE" || true
GARBAGE_SHARE2="8:$(openssl rand -hex 64)"
seal_submit_share "$GARBAGE_SHARE2" 2>&1 || true
RESP="$_SEAL_RESPONSE"

# Should fail reconstruction OR produce a wrong bundle that crypto_set_kek
# loads but is just wrong. Either way, the vault should not encrypt/decrypt
# correctly with the corrupted KEK. But the more important check is that
# we don't crash and shares are still zeroed.
if [ "${#_SHARES_COLLECTED[@]}" -eq 0 ]; then
  pass "error: shares zeroed even after bad reconstruction"
else
  fail "error: shares not cleaned up after bad reconstruction"
fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── root token lifecycle ──"

_reset
seal_init_cluster
INIT_R="$_SEAL_RESPONSE"
TOKEN=$(echo "$INIT_R" | grep -oE '"root_token":"[0-9a-f]+"' | cut -d'"' -f4)

STORED=$(seal_get_root_token)
check "root_token: accessible via getter" "$STORED" "$TOKEN"

seal_clear_root_token
CLEARED=$(seal_get_root_token)
check "root_token: cleared after consumption" "$CLEARED" ""

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
