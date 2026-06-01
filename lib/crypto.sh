#!/usr/bin/env bash
# lib/crypto.sh — envelope encryption
# Every secret gets a random DEK (AES-256-GCM).
# The DEK is wrapped by the in-memory KEK (also AES-256-GCM).
# Neither the KEK nor any plaintext DEK ever touches disk.
#
# Public interface:
#   crypto_encrypt  <plaintext>        → "<wrapped_dek>:<nonce_kek>:<nonce_dek>:<ciphertext>"
#   crypto_decrypt  <envelope>         → plaintext
#   crypto_gen_kek                     → hex KEK (called by seal.sh after reconstruct)
#   crypto_set_kek  <hex>              → loads KEK into memory
#   crypto_clear_kek                   → zeroes KEK variable (called on seal)
#
# Nonce strategy: random 96-bit (12-byte) nonces from /dev/urandom for every
# encryption operation. We accept the birthday-bound risk (~2^48 ops before
# collision probability exceeds 2^-32) rather than a counter, because a
# counter requires atomic persistence across restarts — which would require
# disk writes and reintroduce the sealed/unseal replay risk we are
# specifically avoiding. At expected secret-write rates this bound is safe.

set -euo pipefail

# In-memory KEK. Never exported, never written to disk.
_STRONGBOX_KEK=""

crypto_set_kek() {
  _STRONGBOX_KEK="${1}"
}

crypto_clear_kek() {
  # Overwrite before unsetting — best-effort zeroing in Bash.
  _STRONGBOX_KEK="$(head -c "${#_STRONGBOX_KEK}" /dev/zero | tr '\0' '0')"
  _STRONGBOX_KEK=""
}

crypto_gen_kek() {
  # 256-bit KEK from CSPRNG, returned as hex.
  openssl rand -hex 32
}

crypto_encrypt() {
  local plaintext="${1}"
  [[ -z "${_STRONGBOX_KEK}" ]] && { echo "error: vault is sealed" >&2; return 1; }

  # Random 256-bit DEK and two independent 96-bit nonces from CSPRNG.
  local dek nonce_dek nonce_kek ciphertext wrapped_dek
  dek="$(openssl rand -hex 32)"
  nonce_dek="$(openssl rand -hex 12)"
  nonce_kek="$(openssl rand -hex 12)"

  # Encrypt plaintext with DEK (AES-256-GCM).
  ciphertext="$(printf '%s' "${plaintext}" \
    | openssl enc -aes-256-gcm -K "${dek}" -iv "${nonce_dek}" -nosalt -base64 -A 2>/dev/null)"

  # Wrap DEK with KEK (AES-256-GCM).
  wrapped_dek="$(printf '%s' "${dek}" \
    | openssl enc -aes-256-gcm -K "${_STRONGBOX_KEK}" -iv "${nonce_kek}" -nosalt -base64 -A 2>/dev/null)"

  # Envelope format: wrapped_dek:nonce_kek:nonce_dek:ciphertext  (all base64/hex)
  printf '%s:%s:%s:%s' "${wrapped_dek}" "${nonce_kek}" "${nonce_dek}" "${ciphertext}"
}

crypto_decrypt() {
  local envelope="${1}"
  [[ -z "${_STRONGBOX_KEK}" ]] && { echo "error: vault is sealed" >&2; return 1; }

  local wrapped_dek nonce_kek nonce_dek ciphertext dek plaintext
  IFS=':' read -r wrapped_dek nonce_kek nonce_dek ciphertext <<< "${envelope}"

  # Unwrap DEK using KEK.
  dek="$(printf '%s' "${wrapped_dek}" \
    | openssl enc -d -aes-256-gcm -K "${_STRONGBOX_KEK}" -iv "${nonce_kek}" -nosalt -base64 -A 2>/dev/null)"

  # Decrypt ciphertext using DEK.
  plaintext="$(printf '%s' "${ciphertext}" \
    | openssl enc -d -aes-256-gcm -K "${dek}" -iv "${nonce_dek}" -nosalt -base64 -A 2>/dev/null)"

  printf '%s' "${plaintext}"
}
