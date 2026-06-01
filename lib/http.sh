#!/usr/bin/env bash
# lib/http.sh — HTTP/1.1 request routing + response helpers
#
# Listens on _HTTP_PORT using netcat.
# Parses method, path, headers, body from each raw connection.
# Enforces the sealed gate: all non-/sys routes return 503 when sealed.
# Enforces the leader gate: write routes return 503 with leader hint when
# this node is not the leader (or when quorum is unreachable on minority).
#
# Public interface:
#   http_serve              → blocking listen loop (never returns)
#   http_json  <code> <body>  → writes HTTP/1.1 response to fd 1
#   http_error <code> <msg>   → writes JSON error response

set -euo pipefail

_HTTP_PORT="${STRONGBOX_PORT:-8200}"

http_serve() {
  echo "[$(date -u +%H:%M:%SZ)] strongbox ${_NODE_ID} listening on :${_HTTP_PORT}" >&2
  while true; do
    nc -l -p "${_HTTP_PORT}" -q 1 2>/dev/null | _http_handle_connection || true
  done
}

_http_handle_connection() {
  local raw_request_line token="" body="" headers=""

  # Read request line.
  IFS= read -r raw_request_line
  raw_request_line="${raw_request_line%$'\r'}"
  local method path
  read -r method path _ <<< "${raw_request_line}"

  # Read headers until blank line.
  local content_length=0
  while IFS= read -r line; do
    line="${line%$'\r'}"
    [[ -z "${line}" ]] && break
    headers+="${line}\n"

    case "${line}" in
      Authorization:\ Bearer\ *) token="${line#Authorization: Bearer }" ;;
      Content-Length:\ *)        content_length="${line#Content-Length: }" ;;
      content-length:\ *)        content_length="${line#content-length: }" ;;
    esac
  done

  # Read body.
  if [[ "${content_length}" -gt 0 ]]; then
    body="$(head -c "${content_length}")"
  fi

  # ── gate: sealed ──────────────────────────────────────────────────────
  if seal_is_sealed; then
    case "${path}" in
      /v1/sys/init|/v1/sys/unseal|/v1/sys/health) ;;
      *) http_json 503 '{"error":"vault is sealed"}'; return ;;
    esac
  fi

  # ── gate: leader (writes only, excluding /sys/* bootstrap paths) ──────
  # /sys/init, /sys/unseal, /sys/seal are NOT consensus writes — they
  # manipulate per-node state (KEK in memory). The operator must be able
  # to call them on any node, especially before unseal when leader
  # election may not have produced a stable leader yet.
  local write_method=false
  [[ "${method}" == "PUT" || "${method}" == "POST" || \
     "${method}" == "DELETE" ]] && write_method=true

  local is_sys_path=false
  [[ "${path}" == /v1/sys/* ]] && is_sys_path=true

  if ${write_method} && ! ${is_sys_path} && ! consensus_is_leader; then
    # Minority partition: refuse entirely.
    if ! consensus_quorum_reachable; then
      http_json 503 '{"error":"minority partition — writes refused"}'; return
    fi
    # Follower with quorum: redirect.
    local leader; leader="$(consensus_leader_hint)"
    http_json 307 "$(printf '{"error":"not leader","leader":"%s"}' "${leader}")"
    return
  fi

  _http_route "${method}" "${path}" "${body}" "${token}"
}

_http_route() {
  local method="${1}" path="${2}" body="${3}" token="${4}"

  # Strip query string for routing; preserve it for handlers.
  local route_path="${path%%\?*}"
  local query_string=""
  [[ "${path}" == *\?* ]] && query_string="${path#*\?}"

  case "${method} ${route_path}" in
    # ── sys ──────────────────────────────────────────────────────────────
    "POST /v1/sys/init")    _handle_sys_init    "${body}" ;;
    "POST /v1/sys/unseal")  _handle_sys_unseal  "${body}" ;;
    "POST /v1/sys/seal")    _handle_sys_seal    "${token}" ;;
    "GET /v1/sys/health")   _handle_sys_health ;;

    # ── secrets ──────────────────────────────────────────────────────────
    "PUT /v1/secrets/"*)    _handle_secret_put    "${route_path}" "${body}" "${token}" ;;
    "GET /v1/secrets/"*)    _handle_secret_get    "${route_path}" "${query_string}" "${token}" ;;
    "DELETE /v1/secrets/"*) _handle_secret_delete "${route_path}" "${token}" ;;

    # ── dynamic ──────────────────────────────────────────────────────────
    "GET /v1/dynamic-postgres/"*) _handle_dynamic_pg "${route_path}" "${token}" ;;

    # ── auth ─────────────────────────────────────────────────────────────
    "POST /v1/auth/login")  _handle_auth_login  "${body}" ;;
    "POST /v1/auth/revoke") _handle_auth_revoke "${body}" "${token}" ;;
    "GET /v1/auth/self")    _handle_auth_self   "${token}" ;;

    # ── policies ─────────────────────────────────────────────────────────
    "PUT /v1/policies/"*)   _handle_policy_put "${route_path}" "${body}" "${token}" ;;
    "GET /v1/policies/"*)   _handle_policy_get "${route_path}" "${token}" ;;

    # ── leases ───────────────────────────────────────────────────────────
    "POST /v1/leases/"*/renew)  _handle_lease_renew  "${route_path}" "${token}" ;;
    "POST /v1/leases/"*/revoke) _handle_lease_revoke "${route_path}" "${token}" ;;

    # ── audit ────────────────────────────────────────────────────────────
    "GET /v1/audit") _handle_audit_query "${query_string}" "${token}" ;;

    # ── internal cluster (blocked at Nginx; reachable only on Docker bridge) ──
    "POST /internal/vote")      consensus_handle_vote "${body}" ;;
    "POST /internal/heartbeat") consensus_handle_hb   "${body}" ;;

    *) http_error 404 "not found" ;;
  esac
}

# ── response helpers ────────────────────────────────────────────────────────

http_json() {
  local code="${1}" body="${2}"
  printf 'HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
    "${code}" "${#body}" "${body}"
}

http_error() {
  local code="${1}" msg="${2}"
  http_json "${code}" "$(printf '{"error":"%s"}' "${msg}")"
}

# ── handler stubs ───────────────────────────────────────────────────────────
# Each stub maps to a grading scenario. Implement one at a time.

_handle_sys_init() {
  # POST /v1/sys/init — one-time cluster bootstrap.
  # Generates the KEK pair, splits into N Shamir shares via shamir.py,
  # generates a root token, and returns shares + root token to the operator.
  # Cluster remains SEALED — operator must submit K shares to unseal.
  #
  # Idempotency: seal_init_cluster rejects subsequent calls with
  # {"error":"already initialized"}. The cluster never re-issues shares.
  #
  # CRITICAL: do NOT capture seal_init_cluster output via $() — that forks
  # a subshell and _INITIALIZED=true would be lost in the parent process.
  # Read _SEAL_RESPONSE after the call instead.
  seal_init_cluster || true
  local response="${_SEAL_RESPONSE}"

  # If seal_init_cluster rejected (already initialized), return 409.
  if echo "${response}" | grep -q '"error"'; then
    http_json 409 "${response}"
  else
    http_json 200 "${response}"
  fi
}

_handle_sys_unseal() {
  # POST /v1/sys/unseal {share} — submit one share.
  # When K shares collected, vault transitions sealed → unsealed.
  #
  # Body format: {"share":"x:hexbytes"}
  local body="${1}"
  local share
  share="$(echo "${body}" | grep -o '"share":"[^"]*"' | cut -d\" -f4)"

  if [ -z "${share}" ]; then
    http_error 400 "missing share in request body"
    return
  fi

  # CRITICAL: subshell capture would lose _SHARES_COLLECTED mutation.
  # Call directly; read _SEAL_RESPONSE; then explicitly zero the local share.
  seal_submit_share "${share}" || true
  local response="${_SEAL_RESPONSE}"

  # Zero the share local immediately — caller-side memory hygiene.
  # The HTTP handler held the raw share value; that local must not persist.
  local zero
  zero="$(head -c "${#share}" /dev/zero | tr '\0' '0')"
  share="${zero}"
  share=""

  # Status code selection:
  #   200 — share accepted (progress reported, or unsealed)
  #   400 — malformed share
  #   409 — duplicate share OR already unsealed OR not initialized
  case "${response}" in
    *'"error"'*'malformed'*)         http_json 400 "${response}" ;;
    *'"error"'*'duplicate'*)         http_json 409 "${response}" ;;
    *'"error"'*'already unsealed'*)  http_json 409 "${response}" ;;
    *'"error"'*'not initialized'*)   http_json 409 "${response}" ;;
    *'"error"'*'reconstruction'*)    http_json 400 "${response}" ;;
    *)                                http_json 200 "${response}" ;;
  esac
}

_handle_sys_seal() {
  # POST /v1/sys/seal — purge KEK, return to sealed state.
  # Requires authentication: only an authorised caller can re-seal the vault.
  local token="${1}"

  # Sealing while sealed is a no-op error.
  if seal_is_sealed; then
    http_json 409 '{"error":"vault is already sealed"}'
    return
  fi

  if [ -z "${token}" ]; then
    http_error 401 "unauthorized — bearer token required"
    return
  fi

  # Auth check. Until auth.sh is fully wired we accept the root token as
  # a fallback so this endpoint is testable. Once auth_validate is in
  # place the root-token path becomes redundant but harmless.
  local authed=false
  if declare -f auth_validate >/dev/null 2>&1; then
    auth_validate "${token}" && authed=true
  fi
  if ! ${authed} && [ "${token}" = "$(seal_get_root_token)" ]; then
    authed=true
  fi
  if ! ${authed}; then
    http_error 401 "unauthorized — invalid bearer token"
    return
  fi

  # TODO once audit.sh is fully wired: audit_append "${AUTH_TOKEN_ID:-root}" "seal" "/sys/seal"
  seal_seal

  # 204 No Content — sys/seal returns no body per the spec.
  printf 'HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'
}

_handle_sys_health() {
  local sealed="true"; seal_is_sealed || sealed="false"
  local leader; leader="$(consensus_leader_hint)"
  http_json 200 "$(printf \
    '{"sealed":%s,"leader":"%s","term":%d,"node_id":"%s"}' \
    "${sealed}" "${leader}" "${_CURRENT_TERM}" "${_NODE_ID}")"
}

_handle_secret_put() {
  # TODO: validate token + policy (write), envelope-encrypt body.data,
  # call storage_put, audit_append, return 201 {version}.
  http_json 501 '{"error":"not implemented"}'
}

_handle_secret_get() {
  # TODO: validate token + policy (read), storage_get, crypto_decrypt,
  # lease_create, audit_append, return 200 {data, version, lease}.
  http_json 501 '{"error":"not implemented"}'
}

_handle_secret_delete() {
  # TODO: validate token + policy (delete), storage_delete, audit_append, 204.
  http_json 501 '{"error":"not implemented"}'
}

_handle_dynamic_pg() {
  # TODO: validate token + policy, dynamic_postgres_read, audit_append, 200.
  http_json 501 '{"error":"not implemented"}'
}

_handle_auth_login() {
  # TODO: parse username/password from body, call auth_login, audit_append.
  http_json 501 '{"error":"not implemented"}'
}

_handle_auth_revoke() {
  # TODO: validate caller token, parse target token, auth_revoke, audit_append.
  http_json 501 '{"error":"not implemented"}'
}

_handle_auth_self() {
  # TODO: validate token, return auth_self output.
  http_json 501 '{"error":"not implemented"}'
}

_handle_policy_put() {
  # TODO: validate root token, parse name from path, auth_policy_put, 201.
  http_json 501 '{"error":"not implemented"}'
}

_handle_policy_get() {
  # TODO: validate token, parse name from path, auth_policy_get.
  http_json 501 '{"error":"not implemented"}'
}

_handle_lease_renew() {
  # TODO: validate token, parse lease_id from path, lease_renew.
  http_json 501 '{"error":"not implemented"}'
}

_handle_lease_revoke() {
  # TODO: validate token, parse lease_id from path, lease_revoke.
  http_json 501 '{"error":"not implemented"}'
}

_handle_audit_query() {
  # TODO: validate root token, parse token_id from query string, audit_query.
  http_json 501 '{"error":"not implemented"}'
}
