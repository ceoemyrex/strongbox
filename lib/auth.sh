#!/usr/bin/env bash
# lib/auth.sh — token generation, validation, revocation, policy engine
#
# Tokens: opaque, >=32 bytes entropy from /dev/urandom, stored server-side only.
# Passwords: hashed with Argon2id via the argon2 CLI; never stored in plaintext.
# Revocation: synchronous — a revoked token fails on its very next request.
# Policies: path-prefix + capability set (read, write, delete).
#
# Public interface:
#   auth_user_create   <username> <password> <policies_json>  → 0 or error
#   auth_login         <username> <password>                  → {token, policies}
#   auth_validate      <token>       → 0 valid / 1 invalid; sets AUTH_TOKEN_ID
#   auth_revoke        <token>       → 204 or error
#   auth_self          <token>       → {token_id, policies, ttl}
#   auth_policy_check  <token> <op> <path>  → 0 allow / 1 deny
#   auth_policy_put    <name> <rules_json>  → 201
#   auth_policy_get    <name>               → {rules} or 404

set -euo pipefail

# In-memory stores.
declare -A _AUTH_USERS          # username → argon2id hash
declare -A _AUTH_USER_POLICIES  # username → policies JSON array string
declare -A _AUTH_TOKENS         # token_id → metadata JSON
declare -A _AUTH_TOKEN_INDEX    # raw token → token_id  (fast lookup)
declare -A _AUTH_TOKEN_REVOKED  # token_id → 1
declare -A _AUTH_POLICIES       # policy_name → rules JSON

# Set by auth_validate so handlers can read the caller's identity.
AUTH_TOKEN_ID=""
AUTH_TOKEN_POLICIES=""

auth_user_create() {
  local username="${1}" password="${2}" policies="${3:-[]}"

  # Hash password with Argon2id — never store plaintext.
  local salt hash
  salt="$(openssl rand -hex 16)"
  hash="$(echo -n "${password}" | argon2 "${salt}" -id -t 3 -m 12 -p 1 -e)"

  _AUTH_USERS["${username}"]="${hash}"
  _AUTH_USER_POLICIES["${username}"]="${policies}"
}

auth_login() {
  local username="${1}" password="${2}"
  local stored_hash="${_AUTH_USERS[${username}]:-}"

  if [[ -z "${stored_hash}" ]]; then
    echo '{"error":"invalid credentials"}'; return 1
  fi

  # Verify password against stored Argon2id hash.
  local input_hash
  # Extract salt from stored hash (format: $argon2id$...$<salt>$<hash>)
  local salt; salt="$(echo "${stored_hash}" | cut -d'$' -f5)"
  input_hash="$(echo -n "${password}" | argon2 "${salt}" -id -t 3 -m 12 -p 1 -e)"

  if [[ "${input_hash}" != "${stored_hash}" ]]; then
    echo '{"error":"invalid credentials"}'; return 1
  fi

  local token token_id policies
  token="$(openssl rand -hex 32)"
  token_id="$(openssl rand -hex 8)"
  policies="${_AUTH_USER_POLICIES[${username}]:-[]}"

  _AUTH_TOKENS["${token_id}"]="$(printf \
    '{"token_id":"%s","policies":%s,"created_at":%d}' \
    "${token_id}" "${policies}" "$(date +%s)")"
  _AUTH_TOKEN_INDEX["${token}"]="${token_id}"

  printf '{"token":"%s","policies":%s}' "${token}" "${policies}"
}

auth_validate() {
  local token="${1}"
  local token_id="${_AUTH_TOKEN_INDEX[${token}]:-}"

  [[ -z "${token_id}" ]] && return 1
  [[ -n "${_AUTH_TOKEN_REVOKED[${token_id}]:-}" ]] && return 1

  AUTH_TOKEN_ID="${token_id}"
  AUTH_TOKEN_POLICIES="$(echo "${_AUTH_TOKENS[${token_id}]}" \
    | grep -o '"policies":\[[^]]*\]' | cut -d: -f2-)"
  return 0
}

auth_revoke() {
  local token="${1}"
  local token_id="${_AUTH_TOKEN_INDEX[${token}]:-}"
  [[ -z "${token_id}" ]] && { echo '{"error":"token not found"}'; return 1; }
  _AUTH_TOKEN_REVOKED["${token_id}"]=1
}

auth_self() {
  local token="${1}"
  local token_id="${_AUTH_TOKEN_INDEX[${token}]:-}"
  [[ -z "${token_id}" ]] && { echo '{"error":"invalid token"}'; return 1; }
  echo "${_AUTH_TOKENS[${token_id}]}"
}

auth_policy_put() {
  local name="${1}" rules="${2}"
  _AUTH_POLICIES["${name}"]="${rules}"
}

auth_policy_get() {
  local name="${1}"
  local rules="${_AUTH_POLICIES[${name}]:-}"
  [[ -z "${rules}" ]] && { echo '{"error":"policy not found"}'; return 1; }
  echo "${rules}"
}

auth_policy_check() {
  # Evaluates whether a token is permitted to perform <op> on <path>.
  # Policy rule format (JSON): {"path":"secret/app/*","capabilities":["read","write"]}
  # Returns 0 (allow) or 1 (deny).
  local token="${1}" op="${2}" req_path="${3}"
  local token_id="${_AUTH_TOKEN_INDEX[${token}]:-}"
  [[ -z "${token_id}" ]] && return 1

  local policies_json="${AUTH_TOKEN_POLICIES}"
  # TODO: iterate policies, match path prefix with glob, check capability set.
  # Placeholder: deny all until implemented.
  return 1
}
