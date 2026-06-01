#!/usr/bin/env bash
# lib/storage.sh — in-memory storage backend
#
# All secret access goes through this interface.
# Swapping in a persistent backend (BoltDB, SQLite, etc.) means
# replacing only this file — no other lib/ file touches _STORE directly.
#
# Public interface:
#   storage_init
#   storage_put    <path> <envelope>    → version number (integer)
#   storage_get    <path> [version]     → envelope string, or error on stderr
#   storage_delete <path>               → 0, or error on stderr
#   storage_list   <prefix>             → newline-separated paths

set -euo pipefail

# _STORE["path:N"]        = encrypted envelope for version N
# _STORE_VERSION["path"]  = latest version number for path
declare -A _STORE
declare -A _STORE_VERSION

storage_init() {
  _STORE=()
  _STORE_VERSION=()
}

storage_put() {
  local path="${1}" envelope="${2}"
  local current="${_STORE_VERSION["${path}"]:-0}"
  local version=$(( current + 1 ))
  _STORE["${path}:${version}"]="${envelope}"
  _STORE_VERSION["${path}"]="${version}"
  echo "${version}"
}

storage_get() {
  local path="${1}" version="${2:-}"

  if [[ -z "${version}" ]]; then
    version="${_STORE_VERSION["${path}"]:-}"
    if [[ -z "${version}" ]]; then
      echo '{"error":"secret not found"}' >&2; return 1
    fi
  fi

  local envelope="${_STORE["${path}:${version}"]:-}"
  if [[ -z "${envelope}" ]]; then
    echo '{"error":"version not found"}' >&2; return 1
  fi

  echo "${envelope}"
}

storage_delete() {
  local path="${1}"
  local latest="${_STORE_VERSION["${path}"]:-}"
  if [[ -z "${latest}" ]]; then
    echo '{"error":"secret not found"}' >&2; return 1
  fi

  local v
  for (( v = 1; v <= latest; v++ )); do
    unset "_STORE[${path}:${v}]" 2>/dev/null || true
  done
  unset "_STORE_VERSION[${path}]"
}

storage_list() {
  local prefix="${1:-}"
  local key
  for key in "${!_STORE_VERSION[@]}"; do
    [[ -z "${prefix}" || "${key}" == "${prefix}"* ]] && echo "${key}"
  done
}
