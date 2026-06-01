#!/usr/bin/env bash
# lib/lease.sh — lease lifecycle + background reaper
#
# States: active → expired → revoked | revocation_pending
#
# The reaper runs every _LEASE_REAPER_INTERVAL seconds in the background.
# When a lease expires, it calls dynamic_revoke_lease (dynamic.sh).
# If the DB is unreachable, the lease moves to revocation_pending and retries
# with exponential backoff — capped at _REVOCATION_MAX_BACKOFF seconds.
# A failed revocation is NEVER silently dropped.
#
# Public interface:
#   lease_create        <path> <ttl_seconds>  → lease_id
#   lease_get           <lease_id>            → JSON with state
#   lease_renew         <lease_id>            → {new_ttl} or error
#   lease_revoke        <lease_id>            → 0 or error
#   lease_reaper_start                        → forks background loop

set -euo pipefail

declare -A _LEASES             # lease_id → base metadata JSON
declare -A _LEASE_STATE        # lease_id → active|expired|revoked|revocation_pending
declare -A _LEASE_RETRY_AT     # lease_id → epoch seconds for next retry
declare -A _LEASE_RETRY_COUNT  # lease_id → number of revocation attempts

# Loaded from config.yaml at startup by strongbox entrypoint.
_LEASE_DEFAULT_TTL="${LEASE_DEFAULT_TTL:-3600}"
_LEASE_MAX_TTL="${LEASE_MAX_TTL:-86400}"
_LEASE_REAPER_INTERVAL="${LEASE_REAPER_INTERVAL:-10}"
_REVOCATION_MAX_BACKOFF="${REVOCATION_MAX_BACKOFF:-3600}"

lease_create() {
  local path="${1}" ttl="${2:-${_LEASE_DEFAULT_TTL}}"
  [[ "${ttl}" -gt "${_LEASE_MAX_TTL}" ]] && ttl="${_LEASE_MAX_TTL}"

  local lease_id; lease_id="$(openssl rand -hex 16)"
  local expires_at=$(( $(date +%s) + ttl ))

  _LEASES["${lease_id}"]="$(printf \
    '{"lease_id":"%s","path":"%s","ttl":%d,"expires_at":%d}' \
    "${lease_id}" "${path}" "${ttl}" "${expires_at}")"
  _LEASE_STATE["${lease_id}"]="active"

  echo "${lease_id}"
}

lease_get() {
  local lease_id="${1}"
  local meta="${_LEASES[${lease_id}]:-}"
  [[ -z "${meta}" ]] && { echo '{"error":"lease not found"}'; return 1; }

  local state="${_LEASE_STATE[${lease_id}]}"
  # Inject current state — replace closing } with ,"state":"<state>"}
  echo "${meta%\}},\"state\":\"${state}\"}"
}

lease_renew() {
  local lease_id="${1}"
  local state="${_LEASE_STATE[${lease_id}]:-}"

  [[ "${state}" != "active" ]] && {
    echo '{"error":"lease is not active or has expired"}'; return 1; }

  local current_expires
  current_expires="$(echo "${_LEASES[${lease_id}]}" \
    | grep -o '"expires_at":[0-9]*' | cut -d: -f2)"
  local new_expires=$(( current_expires + _LEASE_DEFAULT_TTL ))
  local max_expires=$(( $(date +%s) + _LEASE_MAX_TTL ))
  [[ "${new_expires}" -gt "${max_expires}" ]] && new_expires="${max_expires}"

  _LEASES["${lease_id}"]="$(echo "${_LEASES[${lease_id}]}" \
    | sed "s/\"expires_at\":[0-9]*/\"expires_at\":${new_expires}/")"

  local remaining=$(( new_expires - $(date +%s) ))
  printf '{"new_ttl":%d}' "${remaining}"
}

lease_revoke() {
  local lease_id="${1}"
  local state="${_LEASE_STATE[${lease_id}]:-}"
  [[ -z "${state}" ]] && { echo '{"error":"lease not found"}'; return 1; }

  # Attempt DB-side cleanup for dynamic leases.
  dynamic_revoke_lease "${lease_id}" && {
    _LEASE_STATE["${lease_id}"]="revoked"
  } || {
    _LEASE_STATE["${lease_id}"]="revocation_pending"
    _LEASE_RETRY_AT["${lease_id}"]=$(( $(date +%s) + 10 ))
    _LEASE_RETRY_COUNT["${lease_id}"]=1
  }
}

lease_reaper_start() {
  (
    while true; do
      sleep "${_LEASE_REAPER_INTERVAL}"
      _lease_reaper_tick
    done
  ) &
  disown
}

_lease_reaper_tick() {
  local now; now="$(date +%s)"
  local lease_id

  for lease_id in "${!_LEASE_STATE[@]}"; do
    local state="${_LEASE_STATE[${lease_id}]}"

    case "${state}" in
      active)
        local expires_at
        expires_at="$(echo "${_LEASES[${lease_id}]}" \
          | grep -o '"expires_at":[0-9]*' | cut -d: -f2)"

        if [[ "${now}" -ge "${expires_at}" ]]; then
          _LEASE_STATE["${lease_id}"]="expired"
          dynamic_revoke_lease "${lease_id}" && {
            _LEASE_STATE["${lease_id}"]="revoked"
          } || {
            _LEASE_STATE["${lease_id}"]="revocation_pending"
            _LEASE_RETRY_AT["${lease_id}"]=$(( now + 10 ))
            _LEASE_RETRY_COUNT["${lease_id}"]=1
          }
        fi
        ;;

      revocation_pending)
        local retry_at="${_LEASE_RETRY_AT[${lease_id}]:-0}"
        if [[ "${now}" -ge "${retry_at}" ]]; then
          dynamic_revoke_lease "${lease_id}" && {
            _LEASE_STATE["${lease_id}"]="revoked"
            unset "_LEASE_RETRY_AT[${lease_id}]"
            unset "_LEASE_RETRY_COUNT[${lease_id}]"
          } || {
            local count=$(( ${_LEASE_RETRY_COUNT[${lease_id}]:-1} + 1 ))
            _LEASE_RETRY_COUNT["${lease_id}"]="${count}"
            # Exponential backoff: 10s, 20s, 40s … capped at max.
            local backoff=$(( 10 * (2 ** (count - 1)) ))
            [[ "${backoff}" -gt "${_REVOCATION_MAX_BACKOFF}" ]] && \
              backoff="${_REVOCATION_MAX_BACKOFF}"
            _LEASE_RETRY_AT["${lease_id}"]=$(( now + backoff ))
          }
        fi
        ;;
    esac
  done
}
