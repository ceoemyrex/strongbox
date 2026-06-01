#!/usr/bin/env bash
# lib/audit.sh — tamper-evident HMAC-SHA256 chain
#
# Each log entry covers: index | ts | token_id | op | path | prev_hmac
# Chain property: entry N's HMAC is stored as prev_hash in entry N+1.
# Any modification breaks the chain — detected by audit_verify.
# flock prevents race conditions when multiple ncat handlers append simultaneously.

set -euo pipefail

_AUDIT_LOG_FILE=""
_AUDIT_HMAC_KEY=""

audit_init() {
  _AUDIT_LOG_FILE="${1:-${STRONGBOX_AUDIT_LOG_FILE:-/var/log/strongbox/audit.log}}"
  mkdir -p "$(dirname "${_AUDIT_LOG_FILE}")"
  _AUDIT_HMAC_KEY="${STRONGBOX_AUDIT_HMAC_KEY:-}"
  # Only generate a random key if none was provided via env (survives restarts via env export)
  [[ -z "${_AUDIT_HMAC_KEY}" ]] && _AUDIT_HMAC_KEY="$(openssl rand -hex 32)"
  return 0
}

audit_append() {
  local token_id="$1" op="$2" path="$3"
  [[ -z "${_AUDIT_LOG_FILE}" ]] && return 0
  [[ -z "${_AUDIT_HMAC_KEY}" ]] && _AUDIT_HMAC_KEY="${STRONGBOX_AUDIT_HMAC_KEY:-}"
  [[ -z "${_AUDIT_HMAC_KEY}" ]] && return 0

  local ts; ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local prev_hash="0000000000000000000000000000000000000000000000000000000000000000"
  local index=0

  (
    flock -x 200  # exclusive lock on file descriptor 200
    if [[ -s "${_AUDIT_LOG_FILE}" ]]; then
      local last_line; last_line="$(tail -n 1 "${_AUDIT_LOG_FILE}")"
      index="$(echo "${last_line}" | grep -o '"index":[0-9]*' | cut -d: -f2)"
      prev_hash="$(echo "${last_line}" | grep -o '"hmac":"[^"]*"' | cut -d\" -f4)"
    fi
    index=$(( index + 1 ))

    local payload hmac
    payload="$(printf '%d|%s|%s|%s|%s|%s' "${index}" "${ts}" "${token_id}" "${op}" "${path}" "${prev_hash}")"
    hmac="$(printf '%s' "${payload}" | openssl dgst -sha256 -hmac "${_AUDIT_HMAC_KEY}" | awk '{print $2}')"

    printf '{"index":%d,"ts":"%s","token_id":"%s","op":"%s","path":"%s","prev_hash":"%s","hmac":"%s"}\n' \
      "${index}" "${ts}" "${token_id}" "${op}" "${path}" "${prev_hash}" "${hmac}" >> "${_AUDIT_LOG_FILE}"
  ) 200>"${_AUDIT_LOG_FILE}.lock"
}

# Replays the chain from entry 1, fails on any HMAC or prev_hash mismatch
audit_verify() {
  local log_file="$1"
  _AUDIT_HMAC_KEY="${STRONGBOX_AUDIT_HMAC_KEY:-}"
  [[ -z "${_AUDIT_HMAC_KEY}" ]] && { echo "error: STRONGBOX_AUDIT_HMAC_KEY required" >&2; return 2; }

  local prev_hash="0000000000000000000000000000000000000000000000000000000000000000"
  local line_number=0

  while IFS= read -r line; do
    line_number=$(( line_number + 1 ))
    local index ts token_id op path stored_prev stored_hmac
    index="$(echo "${line}" | grep -o '"index":[0-9]*' | cut -d: -f2)"
    ts="$(echo "${line}" | grep -o '"ts":"[^"]*"' | cut -d\" -f4)"
    token_id="$(echo "${line}" | grep -o '"token_id":"[^"]*"' | cut -d\" -f4)"
    op="$(echo "${line}" | grep -o '"op":"[^"]*"' | cut -d\" -f4)"
    path="$(echo "${line}" | grep -o '"path":"[^"]*"' | cut -d\" -f4)"
    stored_prev="$(echo "${line}" | grep -o '"prev_hash":"[^"]*"' | cut -d\" -f4)"
    stored_hmac="$(echo "${line}" | grep -o '"hmac":"[^"]*"' | cut -d\" -f4)"
    [[ -z "${index}" ]] && index="${line_number}"

    # Check linkage: prev_hash stored in this entry must match previous entry's hmac
    [[ "${stored_prev}" != "${prev_hash}" ]] && { echo "TAMPERED: audit entry index ${index}" >&2; return 1; }

    local payload expected
    payload="$(printf '%s|%s|%s|%s|%s|%s' "${index}" "${ts}" "${token_id}" "${op}" "${path}" "${prev_hash}")"
    expected="$(printf '%s' "${payload}" | openssl dgst -sha256 -hmac "${_AUDIT_HMAC_KEY}" | awk '{print $2}')"
    [[ "${stored_hmac}" != "${expected}" ]] && { echo "TAMPERED: audit entry index ${index}" >&2; return 1; }

    prev_hash="${stored_hmac}"  # advance chain
  done < "${log_file}"

  echo "audit log intact (${line_number} entries verified)"
}

# Returns all entries as a JSON array, optionally filtered by token_id
audit_query() {
  local filter_token="${1:-}"
  [[ -z "${_AUDIT_LOG_FILE}" || ! -f "${_AUDIT_LOG_FILE}" ]] && { echo '[]'; return; }

  local results=()
  while IFS= read -r line; do
    [[ -z "${filter_token}" || "${line}" == *"\"token_id\":\"${filter_token}\""* ]] && results+=("${line}")
  done < "${_AUDIT_LOG_FILE}"

  [[ "${#results[@]}" -eq 0 ]] && { echo '[]'; return; }
  printf '['
  local i; for (( i = 0; i < ${#results[@]}; i++ )); do
    (( i > 0 )) && printf ','
    printf '%s' "${results[$i]}"
  done
  printf ']'
}
