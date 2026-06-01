#!/usr/bin/env bash
# lib/seal.sh — seal/unseal + Shamir orchestration
#
# Vault states:
#   uninitialised → initialized + sealed → unsealed
#
# Key files on tmpfs (RUN_DIR = /dev/shm/strongbox):
#   kek           — enc_key + hmac_key (64+64 hex chars), written by unseal, wiped by seal
#   shares        — accumulates share strings one per line until threshold reached
#   init_done     — presence-only sentinel: cluster has been initialized
#   root_token    — plaintext root token (bootstrap only, stays on tmpfs)
#
# SEALED_FILE (/data/sealed) presence = sealed; its removal = unsealed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHAMIR_PY="${SCRIPT_DIR}/shamir.py"
RUN_DIR="${RUN_DIR:-/dev/shm/strongbox}"
SEALED_FILE="${SEALED_FILE:-/data/sealed}"

_SHARES_REQUIRED=0
_SHARES_TOTAL=0
_SEAL_RESPONSE=""   # populated by seal_submit_share / seal_init_cluster for http.sh to read

seal_init() {
  mkdir -p "${RUN_DIR}"
  local config_file="${SCRIPT_DIR}/../config.yaml"
  [[ -f "/etc/strongbox/config.yaml" ]] && config_file="/etc/strongbox/config.yaml"
  if [[ ! -f "${config_file}" ]]; then
    _SHARES_REQUIRED=2; _SHARES_TOTAL=3; return 0
  fi
  # tr -d '\r ' strips Windows CRLF and spaces that awk might carry along
  _SHARES_REQUIRED="$(awk '/^shamir:/{f=1;next} f && /threshold:/{print $2; exit}' "${config_file}" | tr -d '\r ')"
  _SHARES_TOTAL="$(awk '/^shamir:/{f=1;next} f && /shares:/{print $2; exit}' "${config_file}" | tr -d '\r ')"
  _SHARES_REQUIRED="${_SHARES_REQUIRED:-2}"; _SHARES_TOTAL="${_SHARES_TOTAL:-3}"
}

seal_is_sealed()      { [[ -f "${SEALED_FILE}" ]]; }
seal_is_initialized() { [[ -f "${RUN_DIR}/init_done" ]]; }
# || true prevents set -e from firing when no root_token file exists yet
seal_get_root_token() { [[ -f "${RUN_DIR}/root_token" ]] && cat "${RUN_DIR}/root_token" || true; }

seal_init_cluster() {
  _SEAL_RESPONSE=""
  seal_is_initialized && { _SEAL_RESPONSE='{"error":"already initialized"}'; return 1; }

  # Generate 128-byte KEK bundle (enc_key || hmac_key) and split via Shamir GF(2^8)
  local kek_pair enc_key hmac_key
  kek_pair="$(crypto_gen_kek)"; enc_key="${kek_pair%% *}"; hmac_key="${kek_pair##* }"
  local bundle_hex="${enc_key}${hmac_key}"

  local shares_output
  shares_output="$(printf '%s\n' "${bundle_hex}" \
    | python3 "${SHAMIR_PY}" split "${_SHARES_REQUIRED}" "${_SHARES_TOTAL}")"
  [[ -z "${shares_output}" ]] && { _SEAL_RESPONSE='{"error":"shamir split failed"}'; return 1; }

  local root_token; root_token="$(openssl rand -hex 32)"

  # Build JSON array of shares from python output (one share per line)
  local shares_json="[" first=true line
  while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    ${first} && first=false || shares_json="${shares_json},"
    shares_json="${shares_json}\"${line}\""
  done <<< "${shares_output}"
  shares_json="${shares_json}]"

  printf '%s' "${root_token}" > "${RUN_DIR}/root_token"
  touch "${RUN_DIR}/init_done"
  auth_bootstrap_root "${root_token}"

  # Zero sensitive material from local vars (best-effort in Bash)
  bundle_hex=""; enc_key=""; hmac_key=""; kek_pair=""; shares_output=""
  _SEAL_RESPONSE="$(printf '{"shares":%s,"root_token":"%s"}' "${shares_json}" "${root_token}")"
}

seal_submit_share() {
  local share="${1:-}"
  _SEAL_RESPONSE=""

  # Followers can be unsealed with the same shares as the leader.
  # We skip the init_done check on followers — Shamir reconstruction validates the shares.
  seal_is_sealed || { _SEAL_RESPONSE='{"error":"vault is already unsealed"}'; return 1; }

  # Validate format: "{index}:{hexbytes}"
  echo "${share}" | grep -qE '^[0-9]+:[0-9a-f]+$' || \
    { _SEAL_RESPONSE='{"error":"malformed share — expected format x:hexbytes"}'; return 1; }

  local shares_file="${RUN_DIR}/shares"
  touch "${shares_file}"

  grep -qxF "${share}" "${shares_file}" 2>/dev/null && {
    local progress; progress="$(wc -l < "${shares_file}")"
    _SEAL_RESPONSE="$(printf '{"error":"duplicate share","sealed":true,"progress":"%d/%d"}' \
      "${progress}" "${_SHARES_REQUIRED}")"
    return 1
  }

  echo "${share}" >> "${shares_file}"
  local progress; progress="$(wc -l < "${shares_file}")"

  if [[ "${progress}" -ge "${_SHARES_REQUIRED}" ]]; then
    _seal_reconstruct_and_unseal
  else
    _SEAL_RESPONSE="$(printf '{"sealed":true,"progress":"%d/%d"}' "${progress}" "${_SHARES_REQUIRED}")"
  fi
}

_seal_reconstruct_and_unseal() {
  local shares_file="${RUN_DIR}/shares"
  local bundle_hex
  bundle_hex="$(python3 "${SHAMIR_PY}" reconstruct < "${shares_file}" 2>/dev/null)" || {
    rm -f "${shares_file}"
    _SEAL_RESPONSE='{"error":"reconstruction failed"}'; return 1
  }

  # KEK bundle must be exactly 128 hex chars (64-byte enc + 64-byte hmac)
  if [[ "${#bundle_hex}" -ne 128 ]]; then
    rm -f "${shares_file}"; bundle_hex=""
    _SEAL_RESPONSE='{"error":"reconstructed bundle has invalid length"}'; return 1
  fi

  crypto_set_kek "${bundle_hex:0:64}" "${bundle_hex:64:64}"

  # Zero-wipe shares file before deleting
  dd if=/dev/zero of="${shares_file}" bs=1 count="$(wc -c < "${shares_file}")" conv=notrunc 2>/dev/null || true
  rm -f "${shares_file}"
  bundle_hex=""
  rm -f "${SEALED_FILE}"  # removing sealed sentinel = vault is now open

  _SEAL_RESPONSE="$(printf '{"sealed":false,"progress":"%d/%d"}' "${_SHARES_REQUIRED}" "${_SHARES_REQUIRED}")"
}

seal_seal() {
  # Wipe KEK from tmpfs and re-create the sealed sentinel
  crypto_clear_kek
  [[ -f "${RUN_DIR}/shares" ]] && {
    dd if=/dev/zero of="${RUN_DIR}/shares" bs=1 count="$(wc -c < "${RUN_DIR}/shares")" conv=notrunc 2>/dev/null || true
    rm -f "${RUN_DIR}/shares"
  }
  touch "${SEALED_FILE}"
}
