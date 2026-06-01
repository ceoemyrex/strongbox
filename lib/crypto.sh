#!/usr/bin/env bash
# lib/crypto.sh — envelope encryption (AES-256-CTR + HMAC-SHA256)
#
# Envelope: ct_dek|mac_dek|nonce_kek|ct_secret|mac_secret|nonce_dek
# KEK pair on tmpfs so ncat-forked handlers share it.
# Nonce: random 128-bit IVs per call (birthday safe to ~2^48 writes).

set -euo pipefail

RUN_DIR="${RUN_DIR:-/dev/shm/strongbox}"
_STRONGBOX_KEK=""
_STRONGBOX_HMAC_KEK=""

crypto_gen_kek() {
  printf '%s %s' "$(openssl rand -hex 32)" "$(openssl rand -hex 32)"
}

crypto_set_kek() {
  mkdir -p "${RUN_DIR}"
  printf '%s %s' "$1" "$2" > "${RUN_DIR}/kek"
}

_crypto_load_kek() {
  [[ -f "${RUN_DIR}/kek" ]] || return 1
  local pair; pair="$(cat "${RUN_DIR}/kek")"
  _STRONGBOX_KEK="${pair%% *}"
  _STRONGBOX_HMAC_KEK="${pair##* }"
}

crypto_clear_kek() {
  if [[ -f "${RUN_DIR}/kek" ]]; then
    local size; size="$(wc -c < "${RUN_DIR}/kek" 2>/dev/null || echo 130)"
    dd if=/dev/zero of="${RUN_DIR}/kek" bs=1 count="${size}" conv=notrunc 2>/dev/null || true
    rm -f "${RUN_DIR}/kek"
  fi
  _STRONGBOX_KEK=""
  _STRONGBOX_HMAC_KEK=""
}

crypto_is_unsealed() { [[ -f "${RUN_DIR}/kek" ]]; }

_ctr_encrypt() {
  printf '%s' "$3" | openssl enc -aes-256-ctr -K "$1" -iv "$2" -nosalt -base64 -A
}

_ctr_decrypt() {
  printf '%s' "$3" | openssl enc -d -aes-256-ctr -K "$1" -iv "$2" -nosalt -base64 -A
}

_hmac() {
  printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" | awk '{print $2}'
}

_hmac_verify() {
  local got; got="$(_hmac "$1" "$2")"
  local h_got; h_got="$(printf '%s' "${got}" | openssl dgst -sha256 | awk '{print $2}')"
  local h_exp; h_exp="$(printf '%s' "$3"     | openssl dgst -sha256 | awk '{print $2}')"
  [[ "${h_got}" == "${h_exp}" ]]
}

crypto_encrypt() {
  _crypto_load_kek || { echo '{"error":"vault is sealed"}' >&2; return 1; }

  local dek hmac_dek nonce_dek nonce_kek
  dek="$(openssl rand -hex 32)"; hmac_dek="$(openssl rand -hex 32)"
  nonce_dek="$(openssl rand -hex 16)"; nonce_kek="$(openssl rand -hex 16)"

  local ct_secret ct_secret_out mac_secret
  ct_secret="$(_ctr_encrypt "${dek}" "${nonce_dek}" "$1")"
  ct_secret_out="${ct_secret:-.}"
  mac_secret="$(_hmac "${hmac_dek}" "${nonce_dek}:${ct_secret_out}")"

  local dek_bundle ct_dek mac_dek_val
  dek_bundle="${dek}.${hmac_dek}"
  ct_dek="$(_ctr_encrypt "${_STRONGBOX_KEK}" "${nonce_kek}" "${dek_bundle}")"
  mac_dek_val="$(_hmac "${_STRONGBOX_HMAC_KEK}" "${nonce_kek}:${ct_dek}")"

  printf '%s|%s|%s|%s|%s|%s' \
    "${ct_dek}" "${mac_dek_val}" "${nonce_kek}" "${ct_secret_out}" "${mac_secret}" "${nonce_dek}"
}

crypto_decrypt() {
  _crypto_load_kek || { echo '{"error":"vault is sealed"}' >&2; return 1; }

  local ct_dek mac_dek nonce_kek ct_secret mac_secret nonce_dek
  IFS='|' read -r ct_dek mac_dek nonce_kek ct_secret mac_secret nonce_dek <<< "$1"

  [[ -z "${ct_dek}" || -z "${mac_dek}" || -z "${nonce_kek}" || \
     -z "${ct_secret}" || -z "${mac_secret}" || -z "${nonce_dek}" ]] && \
    { echo '{"error":"malformed envelope"}' >&2; return 1; }

  _hmac_verify "${_STRONGBOX_HMAC_KEK}" "${nonce_kek}:${ct_dek}" "${mac_dek}" || \
    { echo '{"error":"outer MAC mismatch"}' >&2; return 1; }

  local dek_bundle dek hmac_dek_inner
  dek_bundle="$(_ctr_decrypt "${_STRONGBOX_KEK}" "${nonce_kek}" "${ct_dek}")"
  IFS='.' read -r dek hmac_dek_inner <<< "${dek_bundle}"
  [[ -z "${dek}" || -z "${hmac_dek_inner}" ]] && { echo '{"error":"DEK unwrap failed"}' >&2; return 1; }

  local ct_secret_actual="${ct_secret}"
  [[ "${ct_secret}" == "." ]] && ct_secret_actual=""

  _hmac_verify "${hmac_dek_inner}" "${nonce_dek}:${ct_secret}" "${mac_secret}" || \
    { echo '{"error":"inner MAC mismatch"}' >&2; return 1; }

  [[ -n "${ct_secret_actual}" ]] && _ctr_decrypt "${dek}" "${nonce_dek}" "${ct_secret_actual}" || printf ''
}
