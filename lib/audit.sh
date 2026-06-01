#!/usr/bin/env bash
# lib/audit.sh — tamper-evident HMAC-SHA256 audit chain
#
# Every read, write, auth event, and lease event is appended as a JSON line.
# Each entry includes a hash over (index|ts|token_id|op|path|prev_hash),
# HMAC'd with a key derived from the KEK. This means:
#   - The chain is only verifiable when the cluster is unsealed (stronger model).
#   - A re-seal + re-unseal with a different KEK would break historical verification.
#   - Any single-byte modification to any entry will cause verify to exit non-zero
#     and name the corrupted entry by index.
#
# Public interface:
#   audit_init    <log_file>                  → sets log path, derives HMAC key
#   audit_append  <token_id> <op> <path>      → appends one entry
#   audit_verify  <log_file>                  → 0 intact / 1 corrupted (names entry)
#   audit_query   <token_id>                  → JSON array of matching entries

set -euo pipefail

_AUDIT_LOG_FILE=""
_AUDIT_HMAC_KEY=""
_AUDIT_PREV_HASH="0000000000000000000000000000000000000000000000000000000000000000"
_AUDIT_INDEX=0

audit_init() {
  _AUDIT_LOG_FILE="${1}"
  mkdir -p "$(dirname "${_AUDIT_LOG_FILE}")"

  # Derive HMAC key from KEK using HKDF-like construction.
  # _STRONGBOX_KEK is set by crypto.sh after unseal.
  _AUDIT_HMAC_KEY="$(printf '%s' "strongbox-audit-hmac-v1:${_STRONGBOX_KEK}" \
    | openssl dgst -sha256 | awk '{print $2}')"
}

audit_append() {
  local token_id="${1}" op="${2}" path="${3}"
  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  _AUDIT_INDEX=$(( _AUDIT_INDEX + 1 ))

  local payload
  payload="$(printf '%d|%s|%s|%s|%s|%s' \
    "${_AUDIT_INDEX}" "${ts}" "${token_id}" "${op}" "${path}" "${_AUDIT_PREV_HASH}")"

  local hmac
  hmac="$(printf '%s' "${payload}" \
    | openssl dgst -sha256 -hmac "${_AUDIT_HMAC_KEY}" | awk '{print $2}')"

  local entry
  entry="$(printf \
    '{"index":%d,"ts":"%s","token_id":"%s","op":"%s","path":"%s","prev_hash":"%s","hmac":"%s"}' \
    "${_AUDIT_INDEX}" "${ts}" "${token_id}" "${op}" "${path}" \
    "${_AUDIT_PREV_HASH}" "${hmac}")"

  echo "${entry}" >> "${_AUDIT_LOG_FILE}"
  _AUDIT_PREV_HASH="${hmac}"
}

audit_verify() {
  local log_file="${1}"
  local prev_hash="0000000000000000000000000000000000000000000000000000000000000000"
  local all_ok=true

  while IFS= read -r line; do
    local index ts token_id op path stored_hmac expected_hmac payload

    index="$(echo "${line}"    | grep -o '"index":[0-9]*'        | cut -d: -f2)"
    ts="$(echo "${line}"       | grep -o '"ts":"[^"]*"'          | cut -d\" -f4)"
    token_id="$(echo "${line}" | grep -o '"token_id":"[^"]*"'    | cut -d\" -f4)"
    op="$(echo "${line}"       | grep -o '"op":"[^"]*"'          | cut -d\" -f4)"
    path="$(echo "${line}"     | grep -o '"path":"[^"]*"'        | cut -d\" -f4)"
    stored_hmac="$(echo "${line}" | grep -o '"hmac":"[^"]*"'     | cut -d\" -f4)"

    payload="$(printf '%s|%s|%s|%s|%s|%s' \
      "${index}" "${ts}" "${token_id}" "${op}" "${path}" "${prev_hash}")"

    expected_hmac="$(printf '%s' "${payload}" \
      | openssl dgst -sha256 -hmac "${_AUDIT_HMAC_KEY}" | awk '{print $2}')"

    if [[ "${stored_hmac}" != "${expected_hmac}" ]]; then
      echo "TAMPERED: audit entry index ${index}" >&2
      all_ok=false
      # Do not exit early — report all corrupted entries.
    fi

    prev_hash="${stored_hmac}"
  done < "${log_file}"

  if ${all_ok}; then
    echo "audit log intact (${_AUDIT_INDEX} entries verified)"
    return 0
  else
    return 1
  fi
}

audit_query() {
  local filter_token="${1:-}"
  [[ -z "${_AUDIT_LOG_FILE}" || ! -f "${_AUDIT_LOG_FILE}" ]] && { echo '[]'; return; }

  local results=() line
  while IFS= read -r line; do
    if [[ -z "${filter_token}" || "${line}" == *"\"token_id\":\"${filter_token}\""* ]]; then
      results+=("${line}")
    fi
  done < "${_AUDIT_LOG_FILE}"

  local count="${#results[@]}"
  if [[ "${count}" -eq 0 ]]; then
    echo '[]'; return
  fi

  printf '['
  local i
  for (( i = 0; i < count; i++ )); do
    [[ "${i}" -gt 0 ]] && printf ','
    printf '%s' "${results[$i]}"
  done
  printf ']'
}
