#!/usr/bin/env bash
# lib/seal.sh — seal/unseal state machine + Shamir orchestration
#
# On boot: sealed. Only /v1/sys/health, /v1/sys/unseal, /v1/sys/init respond.
# Shares are submitted one at a time via seal_submit_share.
# Once K shares arrive, shamir.py reconstructs the KEK, crypto.sh loads it,
# and every share + intermediate buffer is zeroed before the function returns.
#
# Public interface:
#   seal_init          → boots sealed; resets share buffer
#   seal_submit_share  <share_colon_hex>  → progress JSON; unseals when K reached
#   seal_seal          → purges KEK; returns to sealed state
#   seal_is_sealed     → returns 0 if sealed, 1 if unsealed
#   seal_status        → prints JSON {sealed, progress}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHAMIR_PY="${SCRIPT_DIR}/shamir.py"

_SEALED=true
_SHARES_COLLECTED=()
_SHARES_REQUIRED=0

seal_init() {
  _SEALED=true
  _SHARES_COLLECTED=()
  _SHARES_REQUIRED="$(grep 'threshold:' "${SCRIPT_DIR}/../config.yaml" \
    | head -1 | awk '{print $2}')"
}

seal_submit_share() {
  local share="${1}"
  if ! ${_SEALED}; then
    echo '{"error":"already unsealed"}'; return 1
  fi

  _SHARES_COLLECTED+=("${share}")
  local progress="${#_SHARES_COLLECTED[@]}"

  if [[ "${progress}" -ge "${_SHARES_REQUIRED}" ]]; then
    _seal_reconstruct_and_unseal
  else
    printf '{"sealed":true,"progress":"%d/%d"}' "${progress}" "${_SHARES_REQUIRED}"
  fi
}

_seal_reconstruct_and_unseal() {
  # Shares passed to shamir.py via stdin — NOT as CLI arguments.
  # This keeps share values out of /proc/PID/cmdline and shell history.
  local kek_hex
  kek_hex="$(printf '%s\n' "${_SHARES_COLLECTED[@]}" \
    | python3 "${SHAMIR_PY}" reconstruct)"

  if [[ -z "${kek_hex}" ]]; then
    echo '{"error":"reconstruction failed — check shares"}' >&2
    return 1
  fi

  # Load KEK into crypto layer.
  crypto_set_kek "${kek_hex}"

  # Zero every collected share immediately.
  local i
  for i in "${!_SHARES_COLLECTED[@]}"; do
    _SHARES_COLLECTED[$i]="$(printf '%0*d' "${#_SHARES_COLLECTED[$i]}" 0)"
    unset '_SHARES_COLLECTED[$i]'
  done
  _SHARES_COLLECTED=()

  # Zero the local kek_hex buffer.
  kek_hex="$(printf '%0*d' "${#kek_hex}" 0)"
  kek_hex=""

  _SEALED=false
  printf '{"sealed":false,"progress":"%d/%d"}' \
    "${_SHARES_REQUIRED}" "${_SHARES_REQUIRED}"
}

seal_seal() {
  crypto_clear_kek
  _SEALED=true
  _SHARES_COLLECTED=()
}

seal_is_sealed() {
  ${_SEALED} && return 0 || return 1
}

seal_status() {
  local progress="${#_SHARES_COLLECTED[@]}"
  if ${_SEALED}; then
    printf '{"sealed":true,"progress":"%d/%d"}' "${progress}" "${_SHARES_REQUIRED}"
  else
    printf '{"sealed":false,"progress":"%d/%d"}' \
      "${_SHARES_REQUIRED}" "${_SHARES_REQUIRED}"
  fi
}
