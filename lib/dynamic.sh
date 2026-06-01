#!/usr/bin/env bash
# lib/dynamic.sh — dynamic Postgres credential engine
#
# GET /v1/dynamic-postgres/{role} mints a fresh Postgres role on every call:
#   1. Generates a unique username (sb_<8 random hex bytes>).
#   2. Generates a strong password (32 random base64 bytes).
#   3. Runs CREATE ROLE + GRANT against the target Postgres.
#   4. Registers a lease via lease.sh.
#   5. Returns {username, password, lease} — password is returned once only.
#
# Revocation (called by lease reaper in lease.sh):
#   REVOKE ALL + DROP ROLE against target Postgres.
#   Returns non-zero if Postgres is unreachable — lease.sh marks revocation_pending.
#   Retries automatically with exponential backoff — no silent drops.
#
# Public interface:
#   dynamic_postgres_read   <role_template>  → JSON {username, password, lease}
#   dynamic_revoke_lease    <lease_id>       → 0 or non-zero (signals reaper to retry)

set -euo pipefail

# Loaded from config.yaml / environment at startup.
_PG_DSN="${STRONGBOX_PG_DSN:-}"
_DYNAMIC_LEASE_TTL="${DYNAMIC_LEASE_TTL:-3600}"
_DYNAMIC_LEASE_MAX_TTL="${DYNAMIC_LEASE_MAX_TTL:-86400}"

# Maps lease_id → postgres username for revocation lookup.
declare -A _DYNAMIC_LEASE_USER

dynamic_postgres_read() {
  local role_template="${1}"
  [[ -z "${_PG_DSN}" ]] && {
    echo '{"error":"postgres DSN not configured"}' >&2; return 1; }

  local username password lease_id
  username="sb_$(openssl rand -hex 8)"
  password="$(openssl rand -base64 32 | tr -d '=+/' | head -c 32)"

  if ! _dynamic_pg_exec \
    "CREATE ROLE \"${username}\" WITH LOGIN PASSWORD '${password}'; \
     GRANT ${role_template} TO \"${username}\";"; then
    echo '{"error":"failed to create dynamic role in Postgres"}' >&2
    return 1
  fi

  lease_id="$(lease_create "dynamic-postgres/${role_template}" "${_DYNAMIC_LEASE_TTL}")"
  _DYNAMIC_LEASE_USER["${lease_id}"]="${username}"

  printf '{"username":"%s","password":"%s","lease":{"lease_id":"%s","ttl":%d}}' \
    "${username}" "${password}" "${lease_id}" "${_DYNAMIC_LEASE_TTL}"
}

dynamic_revoke_lease() {
  local lease_id="${1}"
  local username="${_DYNAMIC_LEASE_USER[${lease_id}]:-}"

  # Not a dynamic lease — nothing to do on the DB side.
  [[ -z "${username}" ]] && return 0

  if ! _dynamic_pg_exec \
    "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM \"${username}\"; \
     DROP ROLE IF EXISTS \"${username}\";"; then
    # Return non-zero — lease.sh reaper will mark revocation_pending and retry.
    return 1
  fi

  unset "_DYNAMIC_LEASE_USER[${lease_id}]"
  return 0
}

_dynamic_pg_exec() {
  local sql="${1}"
  # psql exits non-zero on connection failure or SQL error.
  # stderr is suppressed here; the calling function handles the return code.
  PGPASSWORD="" psql "${_PG_DSN}" \
    --no-password \
    --single-transaction \
    -c "${sql}" \
    2>/dev/null
}
