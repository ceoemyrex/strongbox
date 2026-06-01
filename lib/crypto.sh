#!/usr/bin/env bash
# lib/crypto.sh — envelope encryption for StrongBox
#
# WHY NOT AES-256-GCM via openssl enc:
#   OpenSSL 3.x CLI (`openssl enc`) does not support AEAD ciphers.
#   Running `openssl enc -aes-256-gcm` exits with "AEAD ciphers not supported".
#   The library supports GCM internally but it is not exposed through the enc
#   subcommand. Rather than shell out to a C helper or violate the Bash-only
#   rule with a Python wrapper, we use the standard AEAD construction:
#
#       AES-256-CTR  (confidentiality)  +  HMAC-SHA256  (authentication)
#
#   This is Encrypt-then-MAC — provably secure under standard assumptions
#   and used in TLS 1.2 cipher suites. It is equivalent in security to GCM
#   when MAC verification is performed before decryption (which it is here).
#
# ENVELOPE STRUCTURE (pipe-delimited — pipes never appear in base64 or hex):
#
#   ct_dek | mac_dek | nonce_kek | ct_secret | mac_secret | nonce_dek
#
#   ct_dek     — DEK bundle (DEK + HMAC_DEK key) encrypted with KEK via CTR
#   mac_dek    — HMAC-SHA256(nonce_kek:ct_dek) using HMAC_KEK    ← outer auth
#   nonce_kek  — 128-bit random IV for the KEK layer (hex)
#   ct_secret  — plaintext encrypted with DEK via CTR (base64)
#   mac_secret — HMAC-SHA256(nonce_dek:ct_secret) using HMAC_DEK  ← inner auth
#   nonce_dek  — 128-bit random IV for the DEK layer (hex)
#
# KEY MATERIAL IN MEMORY:
#   _STRONGBOX_KEK      — 256-bit encryption key for the KEK layer (hex)
#   _STRONGBOX_HMAC_KEK — 256-bit MAC key for the KEK layer (hex)
#   Both live only in memory. Never exported. Never written to disk.
#   Both are cleared on seal via crypto_clear_kek.
#
# NONCE STRATEGY:
#   Random 128-bit IVs from /dev/urandom for every encryption call.
#   128-bit (not 96-bit) because openssl enc -aes-256-ctr requires a
#   full 128-bit block for its IV parameter.
#   Birthday bound: collision probability < 2^-32 after ~2^48 writes.
#   At any realistic secret-write rate this is safe. A counter nonce
#   would require atomic disk persistence across restarts — which
#   reintroduces the sealed/unseal replay risk we specifically avoid.
#
# DEK BUNDLE FORMAT (inside ct_dek, before encryption):
#   <dek_hex>.<hmac_dek_hex>
#   64 hex chars + literal dot + 64 hex chars = 129 chars
#   The dot delimiter is safe because hex output never contains dots.
#
# Public interface:
#   crypto_encrypt    <plaintext>   → envelope string, printed to stdout
#   crypto_decrypt    <envelope>    → plaintext, printed to stdout; exit 1 on auth fail
#   crypto_gen_kek                  → prints two hex keys (KEK HMAC_KEK), space-separated
#   crypto_set_kek    <kek_hex> <hmac_kek_hex>  → loads both keys into memory
#   crypto_clear_kek                → zeroes both key variables (called on seal)
#   crypto_is_unsealed              → exit 0 if unsealed, 1 if sealed

set -euo pipefail

_STRONGBOX_KEK=""
_STRONGBOX_HMAC_KEK=""

# ── key lifecycle ─────────────────────────────────────────────────────────────

crypto_gen_kek() {
  # Generate a fresh KEK pair from CSPRNG.
  # Returns two hex strings space-separated: "<enc_key> <mac_key>"
  # Called once by sys/init; output is split into N Shamir shares.
  local enc_key mac_key
  enc_key="$(openssl rand -hex 32)"
  mac_key="$(openssl rand -hex 32)"
  printf '%s %s' "${enc_key}" "${mac_key}"
}

crypto_set_kek() {
  # Load the reconstructed KEK pair into memory after unseal.
  # Arguments: <enc_key_hex> <mac_key_hex>
  _STRONGBOX_KEK="${1}"
  _STRONGBOX_HMAC_KEK="${2}"
}

crypto_clear_kek() {
  # Overwrite both key variables before clearing — best-effort zeroing in Bash.
  # Bash cannot guarantee OS-level zeroing (the shell may have copied the value
  # internally), but this closes the most obvious window.
  local kek_len="${#_STRONGBOX_KEK}"
  local hmac_len="${#_STRONGBOX_HMAC_KEK}"
  [ "${kek_len}"  -gt 0 ] && _STRONGBOX_KEK="$(head -c "${kek_len}" /dev/zero | tr '\0' '0')"
  [ "${hmac_len}" -gt 0 ] && _STRONGBOX_HMAC_KEK="$(head -c "${hmac_len}" /dev/zero | tr '\0' '0')"
  _STRONGBOX_KEK=""
  _STRONGBOX_HMAC_KEK=""
}

crypto_is_unsealed() {
  [[ -n "${_STRONGBOX_KEK}" ]] && return 0 || return 1
}

# ── core primitives ───────────────────────────────────────────────────────────

# _ctr_encrypt <hex_key> <hex_iv> <plaintext>  → base64 ciphertext
_ctr_encrypt() {
  local key="${1}" iv="${2}" plaintext="${3}"
  printf '%s' "${plaintext}" \
    | openssl enc -aes-256-ctr -K "${key}" -iv "${iv}" -nosalt -base64 -A
}

# _ctr_decrypt <hex_key> <hex_iv> <base64_ct>  → plaintext; exit non-zero on failure
_ctr_decrypt() {
  local key="${1}" iv="${2}" ct="${3}"
  printf '%s' "${ct}" \
    | openssl enc -d -aes-256-ctr -K "${key}" -iv "${iv}" -nosalt -base64 -A
}

# _hmac <hex_key> <message>  → hex digest
_hmac() {
  local key="${1}" msg="${2}"
  printf '%s' "${msg}" \
    | openssl dgst -sha256 -hmac "${key}" \
    | awk '{print $2}'
}

# _hmac_verify <hex_key> <message> <expected_hex>  → exit 0 if match, 1 if not
_hmac_verify() {
  local key="${1}" msg="${2}" expected="${3}"
  local got
  got="$(_hmac "${key}" "${msg}")"
  # Constant-time string comparison is not possible in pure Bash.
  # We use a hash-of-hash comparison to prevent timing oracle on
  # the raw HMAC value — an attacker learning timing on hash(MAC)
  # cannot recover the MAC itself.
  local h_got h_exp
  h_got="$(printf '%s' "${got}"      | openssl dgst -sha256 | awk '{print $2}')"
  h_exp="$(printf '%s' "${expected}" | openssl dgst -sha256 | awk '{print $2}')"
  [[ "${h_got}" == "${h_exp}" ]]
}

# ── public: encrypt ───────────────────────────────────────────────────────────

crypto_encrypt() {
  local plaintext="${1}"
  if ! crypto_is_unsealed; then
    echo '{"error":"vault is sealed"}' >&2; return 1
  fi

  # Fresh random key material for every encryption call.
  local dek hmac_dek nonce_dek nonce_kek
  dek="$(openssl rand -hex 32)"
  hmac_dek="$(openssl rand -hex 32)"
  nonce_dek="$(openssl rand -hex 16)"
  nonce_kek="$(openssl rand -hex 16)"

  # Inner layer: encrypt plaintext with DEK.
  local ct_secret mac_secret ct_secret_out
  ct_secret="$(_ctr_encrypt "${dek}" "${nonce_dek}" "${plaintext}")"
  # Use sentinel for empty ct_secret so IFS split does not collapse fields.
  ct_secret_out="${ct_secret:-.}"
  # MAC is computed over the value that goes INTO the envelope (sentinel or real).
  mac_secret="$(_hmac "${hmac_dek}" "${nonce_dek}:${ct_secret_out}")"

  # Outer layer: wrap DEK bundle with KEK.
  # Bundle format: <dek_hex>.<hmac_dek_hex>  (dot separator, safe in hex)
  local dek_bundle ct_dek mac_dek
  dek_bundle="${dek}.${hmac_dek}"
  ct_dek="$(_ctr_encrypt "${_STRONGBOX_KEK}" "${nonce_kek}" "${dek_bundle}")"
  mac_dek="$(_hmac "${_STRONGBOX_HMAC_KEK}" "${nonce_kek}:${ct_dek}")"

  # Emit envelope. Pipe delimiter — never appears in base64 or hex output.
  printf '%s|%s|%s|%s|%s|%s' \
    "${ct_dek}" "${mac_dek}" "${nonce_kek}" \
    "${ct_secret_out}" "${mac_secret}" "${nonce_dek}"
}

# ── public: decrypt ───────────────────────────────────────────────────────────

crypto_decrypt() {
  local envelope="${1}"
  if ! crypto_is_unsealed; then
    echo '{"error":"vault is sealed"}' >&2; return 1
  fi

  # Parse envelope.
  local ct_dek mac_dek nonce_kek ct_secret mac_secret nonce_dek
  IFS='|' read -r ct_dek mac_dek nonce_kek ct_secret mac_secret nonce_dek \
    <<< "${envelope}"

  if [[ -z "${ct_dek}" || -z "${mac_dek}" || -z "${nonce_kek}" || \
        -z "${ct_secret}" || -z "${mac_secret}" || -z "${nonce_dek}" ]]; then
    echo '{"error":"malformed envelope"}' >&2; return 1
  fi

  # Verify outer MAC FIRST — fail before touching any ciphertext.
  if ! _hmac_verify "${_STRONGBOX_HMAC_KEK}" "${nonce_kek}:${ct_dek}" "${mac_dek}"; then
    echo '{"error":"envelope authentication failed — outer MAC mismatch"}' >&2
    return 1
  fi

  # Unwrap DEK bundle.
  local dek_bundle dek hmac_dek
  dek_bundle="$(_ctr_decrypt "${_STRONGBOX_KEK}" "${nonce_kek}" "${ct_dek}")"
  IFS='.' read -r dek hmac_dek <<< "${dek_bundle}"

  if [[ -z "${dek}" || -z "${hmac_dek}" ]]; then
    echo '{"error":"DEK unwrap produced empty bundle"}' >&2; return 1
  fi

  # Reverse the empty-plaintext sentinel applied during encrypt.
  local ct_secret_actual="${ct_secret}"
  [ "${ct_secret}" = "." ] && ct_secret_actual=""

  # Verify inner MAC before decrypting the secret.
  # MAC was computed over the sentinel value, so use ct_secret (not actual) here.
  if ! _hmac_verify "${hmac_dek}" "${nonce_dek}:${ct_secret}" "${mac_secret}"; then
    echo '{"error":"envelope authentication failed — inner MAC mismatch"}' >&2
    return 1
  fi

  # Decrypt secret (empty string decrypts to empty string correctly).
  [ -n "${ct_secret_actual}" ] && _ctr_decrypt "${dek}" "${nonce_dek}" "${ct_secret_actual}" || printf ''
}
