#!/usr/bin/env bash
# lib/dynamic.sh — dynamic Postgres credentials
#
# Each read request creates a short-lived Postgres role and ties it to a lease.
# On revoke (explicit or TTL expiry), the role is dropped via dynamic_revoke_lease.
# The username:role_template pair is stored in {lease_id}.dyn so the reaper can
# revoke it even across handler restarts.

set -euo pipefail

_PG_DSN="${STRONGBOX_PG_DSN:-}"
_DYNAMIC_LEASE_TTL="${DYNAMIC_LEASE_TTL:-3600}"
_LEASE_STATE_DIR="${STRONGBOX_LEASE_DIR:-/dev/shm/strongbox/leases}"

dynamic_init() {
  mkdir -p "${_LEASE_STATE_DIR}"
}

dynamic_postgres_read() {
  local role_template="$1"
  [[ -z "${_PG_DSN}" ]] && { echo '{"error":"postgres DSN not configured"}' >&2; return 1; }

  # Unique username per credential issuance; password never stored server-side
  local username password
  username="sb_$(openssl rand -hex 8)"
  password="$(openssl rand -hex 16)"

  # Suppress psql output — anything printed here leaks into the HTTP response
  if ! _dynamic_pg_exec \
    "CREATE ROLE \"${username}\" WITH LOGIN PASSWORD '${password}'; \
     GRANT \"${role_template}\" TO \"${username}\";" >/dev/null; then
    echo '{"error":"failed to create dynamic role in Postgres"}' >&2
    return 1
  fi

  local lease_id
  lease_id="$(lease_create "dynamic-postgres/${role_template}" "${_DYNAMIC_LEASE_TTL}")"

  # Persist username+role so revocation knows what to DROP
  printf '%s:%s' "${username}" "${role_template}" \
    > "${_LEASE_STATE_DIR}/${lease_id}.dyn"

  printf '{"username":"%s","password":"%s","lease":{"lease_id":"%s","ttl":%d}}' \
    "${username}" "${password}" "${lease_id}" "${_DYNAMIC_LEASE_TTL}"
}

dynamic_revoke_lease() {
  local lease_id="$1"
  local username="" role_template="readonly"

  if [[ -f "${_LEASE_STATE_DIR}/${lease_id}.dyn" ]]; then
    local dyn; dyn="$(cat "${_LEASE_STATE_DIR}/${lease_id}.dyn")"
    username="${dyn%%:*}"
    role_template="${dyn##*:}"
  fi

  # Nothing to revoke (lease may not be dynamic-postgres)
  [[ -z "${username}" ]] && return 0

  # Revoke privileges and drop the ephemeral role
  if ! _dynamic_pg_exec \
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"${username}\"; \
     REVOKE \"${role_template}\" FROM \"${username}\"; \
     DROP ROLE IF EXISTS \"${username}\";" >/dev/null; then
    return 1
  fi

  rm -f "${_LEASE_STATE_DIR}/${lease_id}.dyn"
}

_dynamic_pg_exec() {
  local sql="$1"
  # --no-password: fail if psql prompts instead of hanging
  # --single-transaction: all-or-nothing for multi-statement SQL
  psql "${_PG_DSN}" --no-password --single-transaction -c "${sql}" 2>/dev/null
}
