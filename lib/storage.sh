#!/usr/bin/env bash
# lib/storage.sh — in-memory (tmpfs) key-value + versioned secret store
#
# Backed by /dev/shm (RAM) so it never touches disk. Swap this file to change
# backends — only these functions are called by the rest of the codebase.
#
# Layout on tmpfs:
#   {safe}.v{N}   — versioned envelope for secret writes
#   {safe}        — symlink-equivalent: always the latest envelope
#   {safe}.meta   — current version number (integer)
#   {safe}        — generic kv entries (for tokens, policies, users)

set -euo pipefail

STORAGE_DIR="${STORAGE_DIR:-/dev/shm/strongbox/secrets}"

storage_init() { mkdir -p "${STORAGE_DIR}"; }

# Slashes in paths become underscores to keep filenames flat
_safe_path() { printf '%s' "$1" | tr '/' '_'; }

# Generic key-value: used by auth (tokens, users, policies)
storage_kv_put() {
  local safe; safe="$(_safe_path "$1")"
  mkdir -p "${STORAGE_DIR}"
  printf '%s' "$2" > "${STORAGE_DIR}/${safe}"
}

storage_kv_get() {
  local safe; safe="$(_safe_path "$1")"
  [[ -f "${STORAGE_DIR}/${safe}" ]] || return 1
  cat "${STORAGE_DIR}/${safe}"
}

storage_kv_delete() {
  local safe; safe="$(_safe_path "$1")"
  rm -f "${STORAGE_DIR}/${safe}"
}

# Versioned secret write — increments version, writes both versioned and latest
storage_put() {
  local path="$1" envelope="$2"
  local safe; safe="$(_safe_path "$path")"
  mkdir -p "${STORAGE_DIR}"

  local version=1
  if [[ -f "${STORAGE_DIR}/${safe}.meta" ]]; then
    version="$(cat "${STORAGE_DIR}/${safe}.meta")"
    version=$(( version + 1 ))
  fi

  printf '%s' "$envelope" > "${STORAGE_DIR}/${safe}.v${version}"  # immutable version copy
  printf '%s' "$envelope" > "${STORAGE_DIR}/${safe}"               # latest pointer
  printf '%s' "$version"  > "${STORAGE_DIR}/${safe}.meta"
  echo "$version"
}

# Reads a specific version or latest if version is empty/"latest"
storage_get() {
  local path="$1" version="${2:-}"
  local safe; safe="$(_safe_path "$path")"

  if [[ -n "$version" && "$version" != "latest" ]]; then
    [[ -f "${STORAGE_DIR}/${safe}.v${version}" ]] || { echo '{"error":"version not found"}' >&2; return 1; }
    cat "${STORAGE_DIR}/${safe}.v${version}"
    return 0
  fi

  [[ -f "${STORAGE_DIR}/${safe}" ]] || { echo '{"error":"secret not found"}' >&2; return 1; }
  cat "${STORAGE_DIR}/${safe}"
}

storage_latest_version() {
  local safe; safe="$(_safe_path "$1")"
  [[ -f "${STORAGE_DIR}/${safe}.meta" ]] || { echo "0"; return; }
  cat "${STORAGE_DIR}/${safe}.meta"
}

# Removes all versions and metadata for a path
storage_delete() {
  local safe; safe="$(_safe_path "$1")"
  rm -f "${STORAGE_DIR}/${safe}" "${STORAGE_DIR}/${safe}".v* "${STORAGE_DIR}/${safe}.meta"
}

storage_list() {
  local safe_prefix; safe_prefix="$(_safe_path "${1:-}")"
  shopt -s nullglob
  for f in "${STORAGE_DIR}/${safe_prefix}"*; do
    local base; base="$(basename "$f")"
    [[ "$base" == *.meta || "$base" == *.v* ]] && continue
    printf '%s\n' "$base" | tr '_' '/'
  done
  shopt -u nullglob
}
