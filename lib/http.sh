#!/usr/bin/env bash
# lib/http.sh — HTTP routing + handlers
#
# Sourced by bin/http-handler (one ncat-forked process per connection).
# Reads one request from stdin, writes HTTP response to stdout.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${APP_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
LIB_DIR="${LIB_DIR:-${APP_DIR}/lib}"

for _mod in storage crypto seal auth audit lease dynamic consensus; do
  [[ -f "${LIB_DIR}/${_mod}.sh" ]] && source "${LIB_DIR}/${_mod}.sh"
done

_NODE_ID="${STRONGBOX_NODE_ID:-node-1}"
SEALED_FILE="${SEALED_FILE:-/data/sealed}"

http_json() {
  local code="$1" body="$2" reason
  case "${code}" in
    200) reason="OK";;201) reason="Created";;204) reason="No Content";;
    307) reason="Temporary Redirect";;400) reason="Bad Request";;
    401) reason="Unauthorized";;403) reason="Forbidden";;404) reason="Not Found";;
    409) reason="Conflict";;503) reason="Service Unavailable";;*) reason="OK";;
  esac
  printf 'HTTP/1.1 %s %s\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s' \
    "${code}" "${reason}" "${#body}" "${body}"
}

http_error() { http_json "$1" "$(printf '{"error":"%s"}' "$2")"; }

http_no_content() {
  printf 'HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n'
}

_json_get() {
  python3 -c "import json,sys
d=json.load(sys.stdin)
v=d.get('$2')
if v is None: print('')
elif isinstance(v,(dict,list)): print(json.dumps(v))
else: print(v)" <<< "$1" 2>/dev/null
}

http_handle_connection() {
  local request_line="" content_length=0 auth_header="" body="" line=""

  IFS= read -r request_line || return 0
  request_line="${request_line//$'\r'/}"
  [[ -z "${request_line}" ]] && return 0

  local method path version
  method="${request_line%% *}"
  local rest="${request_line#* }"
  path="${rest%% *}"

  while IFS= read -r line; do
    line="${line//$'\r'/}"
    [[ -z "${line}" ]] && break
    case "${line,,}" in
      content-length:*) content_length="$(echo "${line#*:}" | tr -d '[:space:]')" ;;
      authorization:*)  auth_header="$(echo "${line#*:}" | sed 's/^[[:space:]]*//')" ;;
    esac
  done

  if [[ "${content_length}" =~ ^[0-9]+$ && "${content_length}" -gt 0 ]]; then
    IFS= read -r -N "${content_length}" body || true
  fi

  local token=""
  [[ "${auth_header}" == Bearer\ * ]] && token="${auth_header#Bearer }"

  seal_init
  _http_route "${method}" "${path}" "${body}" "${token}"
}

_http_route() {
  local method="$1" raw_path="$2" body="$3" token="$4"
  local path="${raw_path%%\?*}"
  [[ "${path}" != "/" ]] && path="${path%/}"
  local qs=""; [[ "${raw_path}" == *\?* ]] && qs="${raw_path#*\?}"
  local rp="${path#/v1/}"

  if seal_is_sealed; then
    case "${method} ${path}" in
      *"/v1/sys/health"|*"/v1/sys/unseal"|*"/v1/sys/init"|*"/internal/"*) ;;
      *) http_error 503 "vault is sealed"; return ;;
    esac
  fi

  case "${method}" in
    PUT|POST|DELETE)
      case "${path}" in
        /v1/sys/*|/internal/*|/v1/auth/login) ;;
        *)
          local role; role="$(_cs_read role 2>/dev/null || echo follower)"
          if [[ "${role}" != "leader" ]]; then
            consensus_quorum_reachable 2>/dev/null || { http_error 503 "minority partition — writes refused"; return; }
            http_json 307 "$(printf '{"error":"not leader","leader":"%s"}' "$(consensus_leader_hint 2>/dev/null)")"
            return
          fi ;;
      esac ;;
  esac

  case "${path}" in
    /v1/sys/*|/internal/*|/v1/auth/login) ;;
    *) if [[ -z "${token}" ]] || ! auth_validate "${token}"; then
         http_error 401 "unauthorized"; return
       fi ;;
  esac

  case "${method} ${path}" in
    "POST /v1/sys/init")    _h_init "${body}" ;;
    "POST /v1/sys/unseal")  _h_unseal "${body}" ;;
    "POST /v1/sys/seal")    _h_seal "${token}" ;;
    "GET /v1/sys/health")   _h_health ;;

    "PUT /v1/secrets/"*)    _h_secret_put "${rp#secrets/}" "${body}" "${token}" ;;
    "GET /v1/secrets/"*)    _h_secret_get "${rp#secrets/}" "${qs}" "${token}" ;;
    "DELETE /v1/secrets/"*) _h_secret_del "${rp#secrets/}" "${token}" ;;

    "GET /v1/dynamic-postgres/"*) _h_dynamic "${rp#dynamic-postgres/}" "${token}" ;;

    "POST /v1/auth/login")  _h_login "${body}" ;;
    "POST /v1/auth/revoke") _h_revoke "${body}" "${token}" ;;
    "GET /v1/auth/self")    _h_self "${token}" ;;

    "PUT /v1/users/"*)      _h_user_put "${rp#users/}" "${body}" "${token}" ;;

    "PUT /v1/policies/"*)   _h_pol_put "${rp#policies/}" "${body}" "${token}" ;;
    "GET /v1/policies/"*)   _h_pol_get "${rp#policies/}" "${token}" ;;

    "POST /v1/leases/"*/renew)  _h_lease_renew "${rp}" "${token}" ;;
    "POST /v1/leases/"*/revoke) _h_lease_revoke "${rp}" "${token}" ;;

    "GET /v1/audit") _h_audit "${qs}" "${token}" ;;

    "POST /internal/vote")
      consensus_handle_vote "${body}"; http_json 200 "${_CONSENSUS_RESPONSE}" ;;
    "POST /internal/heartbeat")
      consensus_handle_hb "${body}"; http_json 200 "${_CONSENSUS_RESPONSE}" ;;

    *) http_error 404 "not found" ;;
  esac
}

_h_init() {
  seal_is_initialized && { http_error 409 "already initialized"; return; }
  seal_init_cluster || true
  case "${_SEAL_RESPONSE}" in *'"error"'*) http_json 400 "${_SEAL_RESPONSE}";; *) http_json 200 "${_SEAL_RESPONSE}";; esac
}

_h_unseal() {
  local share; share="$(_json_get "$1" share)"
  [[ -z "${share}" ]] && { http_error 400 "missing share in request body"; return; }
  seal_submit_share "${share}" || true
  share=""
  case "${_SEAL_RESPONSE}" in
    *'"error"'*'not initialized'*|*'"error"'*'already unsealed'*|*'"error"'*'duplicate'*) http_json 409 "${_SEAL_RESPONSE}" ;;
    *'"error"'*) http_json 400 "${_SEAL_RESPONSE}" ;;
    *) http_json 200 "${_SEAL_RESPONSE}" ;;
  esac
}

_h_seal() {
  [[ -z "$1" ]] || ! auth_validate "$1" && { http_error 401 "unauthorized"; return; }
  seal_seal; http_no_content
}

_h_health() {
  local sealed="true"; seal_is_sealed || sealed="false"
  http_json 200 "$(printf '{"sealed":%s,"leader":"%s","term":%d,"node_id":"%s"}' \
    "${sealed}" "$(consensus_leader_hint 2>/dev/null)" "$(_consensus_read_term 2>/dev/null || echo 0)" "${_NODE_ID}")"
}

_h_secret_put() {
  auth_policy_check "${3}" "write" "secret/$1" || { http_error 403 "forbidden"; return; }
  local data; data="$(_json_get "$2" data)"
  [[ -z "${data}" ]] && { http_error 400 "missing data"; return; }
  local env; env="$(crypto_encrypt "${data}")" || { http_error 500 "encryption failed"; return; }
  local ver; ver="$(storage_put "$1" "${env}")"
  audit_append "${AUTH_TOKEN_ID:-anon}" "write" "secret/$1" 2>/dev/null || true
  http_json 201 "$(printf '{"version":%d}' "${ver}")"
}

_h_secret_get() {
  auth_policy_check "${3}" "read" "secret/$1" || { http_error 403 "forbidden"; return; }
  local ver=""; [[ "$2" == *version=* ]] && ver="$(echo "$2" | grep -o 'version=[0-9]*' | cut -d= -f2)"
  local env; env="$(storage_get "$1" "${ver}" 2>/dev/null)" || { http_error 404 "secret not found"; return; }
  local pt; pt="$(crypto_decrypt "${env}")" || { http_error 500 "decryption failed"; return; }
  local lv; lv="$(storage_latest_version "$1")"; [[ -z "${ver}" ]] && ver="${lv}"
  local lid ttl; ttl="${LEASE_DEFAULT_TTL:-3600}"
  lid="$(lease_create "secret/$1" "${ttl}" 2>/dev/null || echo "")"
  audit_append "${AUTH_TOKEN_ID:-anon}" "read" "secret/$1" 2>/dev/null || true
  if [[ -n "${lid}" ]]; then
    http_json 200 "$(printf '{"data":%s,"version":%d,"lease":{"lease_id":"%s","ttl":%d}}' "${pt}" "${ver}" "${lid}" "${ttl}")"
  else
    http_json 200 "$(printf '{"data":%s,"version":%d}' "${pt}" "${ver}")"
  fi
}

_h_secret_del() {
  auth_policy_check "${2}" "delete" "secret/$1" || { http_error 403 "forbidden"; return; }
  storage_delete "$1"
  audit_append "${AUTH_TOKEN_ID:-anon}" "delete" "secret/$1" 2>/dev/null || true
  http_no_content
}

_h_dynamic() {
  auth_policy_check "${2}" "read" "dynamic-postgres/$1" || { http_error 403 "forbidden"; return; }
  local r; r="$(dynamic_postgres_read "$1")" || { http_error 500 "failed to create dynamic credentials"; return; }
  audit_append "${AUTH_TOKEN_ID:-anon}" "read" "dynamic-postgres/$1" 2>/dev/null || true
  http_json 200 "${r}"
}

_h_login() {
  local u p; u="$(_json_get "$1" username)"; p="$(_json_get "$1" password)"
  [[ -z "${u}" || -z "${p}" ]] && { http_error 400 "missing username or password"; return; }
  local r; r="$(auth_login "${u}" "${p}")" || { http_error 401 "invalid credentials"; return; }
  audit_append "anon" "login" "auth/login/${u}" 2>/dev/null || true
  http_json 200 "${r}"
}

_h_revoke() {
  [[ -z "$2" ]] || ! auth_validate "$2" && { http_error 401 "unauthorized"; return; }
  local t; t="$(_json_get "$1" token)"
  [[ -z "${t}" ]] && { http_error 400 "missing token field"; return; }
  auth_revoke "${t}"
  audit_append "${AUTH_TOKEN_ID:-anon}" "revoke" "auth/revoke" 2>/dev/null || true
  http_no_content
}

_h_self() {
  [[ -z "$1" ]] || ! auth_validate "$1" && { http_error 401 "unauthorized"; return; }
  http_json 200 "$(auth_self "$1")"
}

_h_user_put() {
  local username="$1" body="$2" token="$3"
  local pw; pw="$(_json_get "${body}" password)"
  local pol; pol="$(_json_get "${body}" policies)"
  [[ -z "${pw}" ]] && { http_error 400 "missing password"; return; }
  [[ -z "${pol}" ]] && pol='[]'
  auth_user_create "${username}" "${pw}" "${pol}"
  http_json 201 '{"status":"created"}'
}

_h_pol_put() {
  local rules; rules="$(_json_get "$2" rules)"
  [[ -z "${rules}" ]] && { http_error 400 "missing rules"; return; }
  auth_policy_put "$1" "${rules}"
  http_json 201 '{"status":"created"}'
}

_h_pol_get() {
  local r; r="$(auth_policy_get "$1" 2>/dev/null)" || { http_error 404 "policy not found"; return; }
  http_json 200 "${r}"
}

_h_lease_renew() {
  local id; id="$(echo "$1" | sed 's|leases/||;s|/renew||')"
  local r; r="$(lease_renew "${id}")" || { http_error 400 "${r}"; return; }
  http_json 200 "${r}"
}

_h_lease_revoke() {
  local id; id="$(echo "$1" | sed 's|leases/||;s|/revoke||')"
  lease_revoke "${id}" || { http_error 400 "lease not found"; return; }
  http_no_content
}

_h_audit() {
  local ft=""; [[ "$1" == *token=* ]] && ft="$(echo "$1" | grep -o 'token=[^&]*' | cut -d= -f2)"
  http_json 200 "$(audit_query "${ft}")"
}
