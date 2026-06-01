#!/usr/bin/env bash
# lib/lease.sh — lease lifecycle + background reaper
#
# States: active → expired → revoked | revocation_pending
# File layout: ${dir}/${id}.meta (JSON), ${id}.state, ${id}.retry

set -euo pipefail

_LEASE_DEFAULT_TTL="${LEASE_DEFAULT_TTL:-3600}"
_LEASE_MAX_TTL="${LEASE_MAX_TTL:-86400}"
_LEASE_REAPER_INTERVAL="${LEASE_REAPER_INTERVAL:-5}"
_REVOCATION_MAX_BACKOFF="${REVOCATION_MAX_BACKOFF:-3600}"
_LEASE_STATE_DIR="${STRONGBOX_LEASE_DIR:-/dev/shm/strongbox/leases}"

lease_create() {
  local path="$1" ttl="${2:-${_LEASE_DEFAULT_TTL}}"
  (( ttl > _LEASE_MAX_TTL )) && ttl="${_LEASE_MAX_TTL}"

  local lease_id; lease_id="$(openssl rand -hex 16)"
  local expires_at=$(( $(date +%s) + ttl ))
  mkdir -p "${_LEASE_STATE_DIR}"

  printf '{"lease_id":"%s","path":"%s","ttl":%d,"expires_at":%d}' \
    "${lease_id}" "${path}" "${ttl}" "${expires_at}" > "${_LEASE_STATE_DIR}/${lease_id}.meta"
  printf 'active' > "${_LEASE_STATE_DIR}/${lease_id}.state"
  echo "${lease_id}"
}

lease_get() {
  local lease_id="$1"
  [[ -f "${_LEASE_STATE_DIR}/${lease_id}.meta" ]] || { echo '{"error":"lease not found"}'; return 1; }
  local meta state
  meta="$(cat "${_LEASE_STATE_DIR}/${lease_id}.meta")"
  state="$(cat "${_LEASE_STATE_DIR}/${lease_id}.state" 2>/dev/null || echo unknown)"
  echo "${meta%\}},\"state\":\"${state}\"}"
}

lease_renew() {
  local lease_id="$1"
  [[ -f "${_LEASE_STATE_DIR}/${lease_id}.state" ]] || { echo '{"error":"lease not found"}'; return 1; }
  local state; state="$(cat "${_LEASE_STATE_DIR}/${lease_id}.state")"
  [[ "${state}" != "active" ]] && { echo '{"error":"lease is not active"}'; return 1; }

  local meta; meta="$(cat "${_LEASE_STATE_DIR}/${lease_id}.meta")"
  local cur_exp; cur_exp="$(echo "${meta}" | grep -o '"expires_at":[0-9]*' | cut -d: -f2)"
  local new_exp=$(( cur_exp + _LEASE_DEFAULT_TTL ))
  local max_exp=$(( $(date +%s) + _LEASE_MAX_TTL ))
  (( new_exp > max_exp )) && new_exp="${max_exp}"

  printf '%s' "$(echo "${meta}" | sed "s/\"expires_at\":[0-9]*/\"expires_at\":${new_exp}/")" \
    > "${_LEASE_STATE_DIR}/${lease_id}.meta"
  printf '{"new_ttl":%d}' "$(( new_exp - $(date +%s) ))"
}

lease_revoke() {
  local lease_id="$1"
  [[ -f "${_LEASE_STATE_DIR}/${lease_id}.state" ]] || { echo '{"error":"lease not found"}'; return 1; }
  if dynamic_revoke_lease "${lease_id}" 2>/dev/null; then
    printf 'revoked' > "${_LEASE_STATE_DIR}/${lease_id}.state"
    rm -f "${_LEASE_STATE_DIR}/${lease_id}.retry"
  else
    printf 'revocation_pending' > "${_LEASE_STATE_DIR}/${lease_id}.state"
    printf '%d 1' "$(( $(date +%s) + 10 ))" > "${_LEASE_STATE_DIR}/${lease_id}.retry"
  fi
}

lease_reaper_start() {
  export _LEASE_STATE_DIR STRONGBOX_PG_DSN
  ( while true; do sleep "${_LEASE_REAPER_INTERVAL}"; _lease_reaper_tick; done ) &
  disown
}

_lease_reaper_tick() {
  local now; now="$(date +%s)"
  shopt -s nullglob
  for sf in "${_LEASE_STATE_DIR}"/*.state; do
    local id; id="$(basename "${sf}" .state)"
    local state; state="$(cat "${sf}" 2>/dev/null || echo unknown)"
    [[ -f "${_LEASE_STATE_DIR}/${id}.meta" ]] || continue

    case "${state}" in
      active)
        local ea; ea="$(grep -o '"expires_at":[0-9]*' "${_LEASE_STATE_DIR}/${id}.meta" | cut -d: -f2)"
        if (( now >= ea )); then
          printf 'expired' > "${sf}"
          if dynamic_revoke_lease "${id}" 2>/dev/null; then
            printf 'revoked' > "${sf}"; rm -f "${_LEASE_STATE_DIR}/${id}.dyn"
          else
            printf 'revocation_pending' > "${sf}"
            printf '%d 1' "$(( now + 10 ))" > "${_LEASE_STATE_DIR}/${id}.retry"
          fi
        fi ;;
      revocation_pending)
        [[ -f "${_LEASE_STATE_DIR}/${id}.retry" ]] || continue
        local rd; rd="$(cat "${_LEASE_STATE_DIR}/${id}.retry")"
        local ra="${rd%% *}" cnt="${rd##* }"
        if (( now >= ra )); then
          if dynamic_revoke_lease "${id}" 2>/dev/null; then
            printf 'revoked' > "${sf}"; rm -f "${_LEASE_STATE_DIR}/${id}.retry" "${_LEASE_STATE_DIR}/${id}.dyn"
          else
            cnt=$(( cnt + 1 )); local bo=$(( 10 * (2 ** (cnt - 1)) ))
            (( bo > _REVOCATION_MAX_BACKOFF )) && bo="${_REVOCATION_MAX_BACKOFF}"
            printf '%d %d' "$(( now + bo ))" "${cnt}" > "${_LEASE_STATE_DIR}/${id}.retry"
          fi
        fi ;;
    esac
  done
  shopt -u nullglob
}
