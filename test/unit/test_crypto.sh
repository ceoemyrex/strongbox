#!/usr/bin/env bash
# test/unit/test_crypto.sh — unit tests for lib/crypto.sh
#
# Run from repo root:
#   bash test/unit/test_crypto.sh
#
# Tests are grouped:
#   Key lifecycle   — gen, set, clear, sealed gate
#   Encrypt/Decrypt — roundtrip, special chars, idempotency
#   Authentication  — tamper detection on every field
#   Nonce           — uniqueness across calls
#   Sealed gate     — operations blocked when KEK not loaded
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO}/lib/crypto.sh"

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

check_nonempty() {
  local label="$1" value="$2"
  if [ -n "$value" ]; then pass "$label"
  else fail "$label — got empty string"; fi
}

check_contains() {
  local label="$1" haystack="$2" needle="$3"
  if echo "$haystack" | grep -qF "$needle"; then pass "$label"
  else fail "$label — '$needle' not found in output"; fi
}

# ── helpers ───────────────────────────────────────────────────────────────────

_load_test_kek() {
  local pair
  pair="$(crypto_gen_kek)"
  local kek hmac_kek
  kek="${pair%% *}"
  hmac_kek="${pair##* }"
  crypto_set_kek "$kek" "$hmac_kek"
}

_count_pipes() {
  local s="$1"
  echo "$s" | tr -cd '|' | wc -c | tr -d ' '
}

# ═════════════════════════════════════════════════════════════════════════════
echo "── key lifecycle ──"

# crypto_gen_kek produces two hex strings
PAIR=$(crypto_gen_kek)
KEK_HEX="${PAIR%% *}"
HMAC_HEX="${PAIR##* }"
check "gen_kek: two tokens" "$(echo "$PAIR" | wc -w | tr -d ' ')" "2"
check "gen_kek: enc key length (64 hex chars = 32 bytes)" "${#KEK_HEX}" "64"
check "gen_kek: mac key length (64 hex chars = 32 bytes)" "${#HMAC_HEX}" "64"
check "gen_kek: enc key is hex" "$(echo "$KEK_HEX" | grep -cE '^[0-9a-f]{64}$')" "1"
check "gen_kek: mac key is hex" "$(echo "$HMAC_HEX" | grep -cE '^[0-9a-f]{64}$')" "1"

# gen_kek produces different keys each call
PAIR2=$(crypto_gen_kek)
if [ "$PAIR" != "$PAIR2" ]; then pass "gen_kek: randomised across calls"
else fail "gen_kek: same keys returned twice — not random"; fi

# set and clear
crypto_set_kek "$KEK_HEX" "$HMAC_HEX"
if crypto_is_unsealed; then pass "is_unsealed: true after set_kek"
else fail "is_unsealed: false after set_kek — bug"; fi

crypto_clear_kek
if ! crypto_is_unsealed; then pass "is_unsealed: false after clear_kek"
else fail "is_unsealed: still true after clear_kek — bug"; fi

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── sealed gate ──"

# All operations must fail when sealed
SEAL_ERR=$(crypto_encrypt "secret" 2>&1) && fail "encrypt: should fail when sealed" \
  || { echo "$SEAL_ERR" | grep -q "sealed" && pass "encrypt: blocked when sealed" \
       || fail "encrypt: wrong error — got '$SEAL_ERR'"; }

FAKE_ENV="ct_dek|mac|nonce_kek|ct_secret|mac_secret|nonce_dek"
SEAL_ERR2=$(crypto_decrypt "$FAKE_ENV" 2>&1) && fail "decrypt: should fail when sealed" \
  || { echo "$SEAL_ERR2" | grep -q "sealed" && pass "decrypt: blocked when sealed" \
       || fail "decrypt: wrong error — got '$SEAL_ERR2'"; }

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── encrypt / decrypt roundtrip ──"

_load_test_kek

# Basic roundtrip
PT="hello strongbox"
ENV=$(crypto_encrypt "$PT")
check_nonempty "encrypt: returns non-empty envelope" "$ENV"
RECOVERED=$(crypto_decrypt "$ENV")
check "decrypt: recovers original plaintext" "$RECOVERED" "$PT"

# Envelope has exactly 5 pipe delimiters (6 fields)
PIPES=$(_count_pipes "$ENV")
check "envelope: has 5 pipe delimiters (6 fields)" "$PIPES" "5"

# Empty string
PT_EMPTY=""
ENV_EMPTY=$(crypto_encrypt "$PT_EMPTY")
RECOVERED_EMPTY=$(crypto_decrypt "$ENV_EMPTY")
check "roundtrip: empty string" "$RECOVERED_EMPTY" "$PT_EMPTY"

# String with colons (database URLs, common secret format)
PT_COLON="postgresql://admin:p4ssw0rd@db.host:5432/mydb"
ENV_COLON=$(crypto_encrypt "$PT_COLON")
RECOVERED_COLON=$(crypto_decrypt "$ENV_COLON")
check "roundtrip: string containing colons" "$RECOVERED_COLON" "$PT_COLON"

# String with pipes (should still work — pipes are in the outer envelope, not the plaintext)
PT_PIPE="value|with|pipes"
ENV_PIPE=$(crypto_encrypt "$PT_PIPE")
RECOVERED_PIPE=$(crypto_decrypt "$ENV_PIPE")
check "roundtrip: string containing pipes" "$RECOVERED_PIPE" "$PT_PIPE"

# JSON value (common secret shape)
PT_JSON='{"username":"admin","password":"s3cr3t!","host":"10.0.0.1"}'
ENV_JSON=$(crypto_encrypt "$PT_JSON")
RECOVERED_JSON=$(crypto_decrypt "$ENV_JSON")
check "roundtrip: JSON secret" "$RECOVERED_JSON" "$PT_JSON"

# Long value (2KB)
PT_LONG=$(head -c 2048 /dev/urandom | base64 -w0 | head -c 2048)
ENV_LONG=$(crypto_encrypt "$PT_LONG")
RECOVERED_LONG=$(crypto_decrypt "$ENV_LONG")
check "roundtrip: 2KB value" "$RECOVERED_LONG" "$PT_LONG"

# Whitespace and special chars
PT_SPECIAL=$'line one\nline two\ttabbed'
ENV_SPECIAL=$(crypto_encrypt "$PT_SPECIAL")
RECOVERED_SPECIAL=$(crypto_decrypt "$ENV_SPECIAL")
check "roundtrip: whitespace and newlines" "$RECOVERED_SPECIAL" "$PT_SPECIAL"

# Same plaintext encrypted twice produces different envelopes (nonce randomness)
ENV_A=$(crypto_encrypt "same secret")
ENV_B=$(crypto_encrypt "same secret")
if [ "$ENV_A" != "$ENV_B" ]; then pass "encrypt: different envelope each call (nonce randomness)"
else fail "encrypt: identical envelopes — nonces not random"; fi

# Decrypt both and get the same plaintext
RA=$(crypto_decrypt "$ENV_A")
RB=$(crypto_decrypt "$ENV_B")
check "decrypt: both envelopes recover same plaintext (A)" "$RA" "same secret"
check "decrypt: both envelopes recover same plaintext (B)" "$RB" "same secret"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── authentication — tamper detection ──"

# Helper: get each field from envelope
_field() { echo "$1" | cut -d'|' -f"$2"; }
_replace_field() {
  local env="$1" pos="$2" val="$3"
  IFS='|' read -r f1 f2 f3 f4 f5 f6 <<< "$env"
  case $pos in
    1) echo "${val}|${f2}|${f3}|${f4}|${f5}|${f6}" ;;
    2) echo "${f1}|${val}|${f3}|${f4}|${f5}|${f6}" ;;
    3) echo "${f1}|${f2}|${val}|${f4}|${f5}|${f6}" ;;
    4) echo "${f1}|${f2}|${f3}|${val}|${f5}|${f6}" ;;
    5) echo "${f1}|${f2}|${f3}|${f4}|${val}|${f6}" ;;
    6) echo "${f1}|${f2}|${f3}|${f4}|${f5}|${val}" ;;
  esac
}
_flip_last_char() {
  local s="$1"
  local len=${#s}
  local last="${s: -1}"
  local replacement
  if [ "$last" = "a" ]; then replacement="b"; else replacement="a"; fi
  echo "${s:0:$((len-1))}${replacement}"
}

TENV=$(crypto_encrypt "tamper test value")

# Tamper ct_dek (field 1)
F1=$(_field "$TENV" 1)
F1_BAD=$(_flip_last_char "$F1")
ENV_T1=$(_replace_field "$TENV" 1 "$F1_BAD")
ERR=$(crypto_decrypt "$ENV_T1" 2>&1) && fail "tamper ct_dek: not detected" \
  || pass "tamper ct_dek: authentication failed correctly"

# Tamper mac_dek (field 2)
F2=$(_field "$TENV" 2)
F2_BAD=$(_flip_last_char "$F2")
ENV_T2=$(_replace_field "$TENV" 2 "$F2_BAD")
ERR=$(crypto_decrypt "$ENV_T2" 2>&1) && fail "tamper mac_dek: not detected" \
  || pass "tamper mac_dek: authentication failed correctly"

# Tamper nonce_kek (field 3)
F3=$(_field "$TENV" 3)
F3_BAD=$(_flip_last_char "$F3")
ENV_T3=$(_replace_field "$TENV" 3 "$F3_BAD")
ERR=$(crypto_decrypt "$ENV_T3" 2>&1) && fail "tamper nonce_kek: not detected" \
  || pass "tamper nonce_kek: authentication failed correctly"

# Tamper ct_secret (field 4)
F4=$(_field "$TENV" 4)
F4_BAD=$(_flip_last_char "$F4")
ENV_T4=$(_replace_field "$TENV" 4 "$F4_BAD")
ERR=$(crypto_decrypt "$ENV_T4" 2>&1) && fail "tamper ct_secret: not detected" \
  || pass "tamper ct_secret: authentication failed correctly"

# Tamper mac_secret (field 5)
F5=$(_field "$TENV" 5)
F5_BAD=$(_flip_last_char "$F5")
ENV_T5=$(_replace_field "$TENV" 5 "$F5_BAD")
ERR=$(crypto_decrypt "$ENV_T5" 2>&1) && fail "tamper mac_secret: not detected" \
  || pass "tamper mac_secret: authentication failed correctly"

# Tamper nonce_dek (field 6)
F6=$(_field "$TENV" 6)
F6_BAD=$(_flip_last_char "$F6")
ENV_T6=$(_replace_field "$TENV" 6 "$F6_BAD")
ERR=$(crypto_decrypt "$ENV_T6" 2>&1) && fail "tamper nonce_dek: not detected" \
  || pass "tamper nonce_dek: authentication failed correctly"

# Truncated envelope
ERR=$(crypto_decrypt "onlyone" 2>&1) && fail "truncated: not detected" \
  || pass "truncated envelope: rejected correctly"

# Wrong KEK — decrypt with a different KEK should fail
PAIR_ALT=$(crypto_gen_kek)
crypto_set_kek "${PAIR_ALT%% *}" "${PAIR_ALT##* }"
ERR=$(crypto_decrypt "$TENV" 2>&1) && fail "wrong KEK: decrypted without error" \
  || pass "wrong KEK: authentication failed correctly"

# Restore correct KEK
_load_test_kek

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── nonce uniqueness ──"

# Generate 50 envelopes for the same plaintext — all nonces must differ
NONCES=()
for i in $(seq 1 50); do
  E=$(crypto_encrypt "nonce test")
  # Extract nonce_dek (field 6) and nonce_kek (field 3)
  N_DEK=$(_field "$E" 6)
  N_KEK=$(_field "$E" 3)
  NONCES+=("${N_DEK}:${N_KEK}")
done

# Check uniqueness
UNIQUE=$(printf '%s\n' "${NONCES[@]}" | sort -u | wc -l | tr -d ' ')
check "nonces: all 50 (nonce_dek:nonce_kek) pairs are unique" "$UNIQUE" "50"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── key isolation ──"

# Encrypt with KEK-A, try to decrypt with KEK-B — must fail
PAIR_A=$(crypto_gen_kek)
crypto_set_kek "${PAIR_A%% *}" "${PAIR_A##* }"
ENV_A=$(crypto_encrypt "isolated secret")

PAIR_B=$(crypto_gen_kek)
crypto_set_kek "${PAIR_B%% *}" "${PAIR_B##* }"
ERR=$(crypto_decrypt "$ENV_A" 2>&1) && fail "key isolation: decrypted with wrong KEK" \
  || pass "key isolation: different KEK correctly rejected"

# Restore original KEK-A and verify it still decrypts
crypto_set_kek "${PAIR_A%% *}" "${PAIR_A##* }"
RECOVERED_A=$(crypto_decrypt "$ENV_A")
check "key isolation: original KEK still decrypts" "$RECOVERED_A" "isolated secret"

# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── seal clears keys ──"

_load_test_kek
ENV_PRE=$(crypto_encrypt "before seal")
crypto_clear_kek

# After clear, encrypt and decrypt must fail
ERR=$(crypto_encrypt "after seal" 2>&1) && fail "post-seal encrypt: should fail" \
  || pass "post-seal encrypt: correctly blocked"

ERR=$(crypto_decrypt "$ENV_PRE" 2>&1) && fail "post-seal decrypt: should fail" \
  || pass "post-seal decrypt: correctly blocked"

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
