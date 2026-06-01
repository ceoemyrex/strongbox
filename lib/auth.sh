#!/usr/bin/env bash
# lib/auth.sh — tokens, passwords (Argon2id), policies
#
# All state via storage_kv_put/get (file-backed, shared across ncat handlers).
# Revocation is synchronous — revoked token fails on next request.

set -euo pipefail

AUTH_TOKEN_ID=""
AUTH_TOKEN_POLICIES=""

auth_init() { storage_init; }

auth_bootstrap_root() {
  local token="$1"
  storage_kv_put "token:${token}:valid" "true"
  storage_kv_put "token:${token}:policies" '["root"]'
  storage_kv_put "token:${token}:created_at" "$(date +%s)"
  storage_kv_put "token:${token}:id" "root"
}

auth_user_create() {
  local username="$1" password="$2" policies="${3:-[]}"
  local salt hash
  salt="$(openssl rand -hex 16)"
  hash="$(printf '%s' "${password}" | argon2 "${salt}" -id -t 3 -m 16 -p 1 -l 32 -e 2>/dev/null)"
  storage_kv_put "user:${username}:hash" "${hash}"
  storage_kv_put "user:${username}:policies" "${policies}"
}

auth_login() {
  local username="$1" password="$2"
  local stored_hash
  stored_hash="$(storage_kv_get "user:${username}:hash" 2>/dev/null)" || {
    echo '{"error":"invalid credentials"}'; return 1
  }

  local valid
  valid="$(python3 - "${password}" "${stored_hash}" <<'PY'
import sys
from argon2 import PasswordHasher
try:
    PasswordHasher().verify(sys.argv[2], sys.argv[1])
    print("ok")
except Exception:
    print("fail")
PY
)"
  [[ "${valid}" != "ok" ]] && { echo '{"error":"invalid credentials"}'; return 1; }

  local token token_id policies
  token="$(openssl rand -hex 32)"
  token_id="$(openssl rand -hex 8)"
  policies="$(storage_kv_get "user:${username}:policies" 2>/dev/null || echo '[]')"

  storage_kv_put "token:${token}:valid" "true"
  storage_kv_put "token:${token}:policies" "${policies}"
  storage_kv_put "token:${token}:created_at" "$(date +%s)"
  storage_kv_put "token:${token}:id" "${token_id}"

  printf '{"token":"%s","policies":%s}' "${token}" "${policies}"
}

auth_validate() {
  local token="$1"
  local valid
  valid="$(storage_kv_get "token:${token}:valid" 2>/dev/null)" || return 1
  [[ "${valid}" != "true" ]] && return 1
  AUTH_TOKEN_ID="$(storage_kv_get "token:${token}:id" 2>/dev/null || echo "")"
  AUTH_TOKEN_POLICIES="$(storage_kv_get "token:${token}:policies" 2>/dev/null || echo '[]')"
}

auth_revoke() {
  local token="$1"
  storage_kv_put "token:${token}:valid" "false"
}

auth_self() {
  local token="$1"
  auth_validate "${token}" || { echo '{"error":"invalid token"}'; return 1; }
  printf '{"token_id":"%s","policies":%s,"ttl":null}' "${AUTH_TOKEN_ID}" "${AUTH_TOKEN_POLICIES}"
}

auth_policy_put() { storage_kv_put "policy:$1" "$2"; }

auth_policy_get() {
  storage_kv_get "policy:$1" 2>/dev/null || { echo '{"error":"policy not found"}'; return 1; }
}

auth_policy_check() {
  local token="$1" op="$2" req_path="$3"
  auth_validate "${token}" || return 1

  local policies="${AUTH_TOKEN_POLICIES}"
  echo "${policies}" | grep -q '"root"' && return 0

  local policy_name
  while IFS= read -r policy_name; do
    [[ -z "${policy_name}" ]] && continue
    local rules_json
    rules_json="$(storage_kv_get "policy:${policy_name}" 2>/dev/null)" || continue
    local rule rule_path capabilities
    while IFS= read -r rule; do
      [[ -z "${rule}" ]] && continue
      rule_path="$(printf '%s' "${rule}" | grep -o '"path":"[^"]*"' | cut -d\" -f4)"
      capabilities="$(printf '%s' "${rule}" | grep -o '"capabilities":\[[^]]*\]' | cut -d: -f2-)"
      _auth_path_matches "${rule_path}" "${req_path}" || continue
      echo "${capabilities}" | grep -q "\"${op}\"" && return 0
    done < <(printf '%s' "${rules_json}" | tr -d '[:space:]' | grep -o '{"path":"[^"]*","capabilities":\[[^]]*\]}')
  done < <(printf '%s' "${policies}" | grep -o '"[^"]*"' | tr -d '"')

  return 1
}

_auth_path_matches() {
  local pattern="$1" req_path="$2"
  if [[ "${pattern}" == *"*" ]]; then
    [[ "${req_path}" == "${pattern%\*}"* ]]
  else
    [[ "${req_path}" == "${pattern}" ]]
  fi
}
