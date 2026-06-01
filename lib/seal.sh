#!/usr/bin/env bash
# lib/seal.sh — seal/unseal state machine + Shamir orchestration
#
# OVERVIEW
#   The vault has three lifecycle states:
#     1. uninitialized  — boot state; only /sys/init responds, everything else 503
#     2. sealed         — KEK exists somewhere as shares; only /sys/health,
#                         /sys/unseal, /sys/seal respond; non-/sys returns 503
#     3. unsealed       — KEK pair loaded in crypto.sh memory; full API responds
#
#   Transitions:
#     init    : uninitialized → sealed     (generates KEK, splits into shares)
#     unseal  : sealed         → unsealed  (collects K shares, reconstructs KEK)
#     seal    : unsealed       → sealed    (zeroes KEK; shares must be resubmitted)
#
# KEK BUNDLE FORMAT
#   crypto.sh now uses TWO 256-bit keys: an encryption key and an HMAC key.
#   Together they form a 64-byte "KEK bundle" — exactly one secret to split:
#
#       bundle_hex = enc_key_hex || hmac_key_hex   (128 hex chars = 64 bytes)
#
#   Shamir splits the 64 raw bytes. Each share is 64 bytes + an x value.
#   Reconstruction produces the 64-byte bundle, which is unbundled at offset 64
#   into enc_key and hmac_key, then loaded into crypto.sh via crypto_set_kek.
#
# MEMORY HYGIENE (the heap-dump test)
#   After unseal, NONE of the following must remain in process memory:
#     - Any submitted share value
#     - The reconstructed bundle
#     - Either half of the KEK pair as a local Bash variable
#
#   Bash cannot guarantee OS-level memory zeroing — the shell may have copied
#   values internally during string operations. We do the strongest available:
#     1. Pass shares to shamir.py via stdin, never argv (cmdline visible in /proc)
#     2. shamir.py uses bytearray and zeroes each byte before exit
#     3. Overwrite the Bash variable with zeroes BEFORE unset
#     4. Clear the entire _SHARES_COLLECTED array
#     5. The kek bundle local is overwritten with zeroes immediately after use
#     6. Submitted shares are also zeroed inside the array
#
#   The remaining KEK pair lives in crypto.sh as _STRONGBOX_KEK and
#   _STRONGBOX_HMAC_KEK — that is the deliberate, audited copy.
#
# Public interface:
#   seal_init                          → loads K, N from config; resets state
#   seal_init_cluster                  → generates KEK, splits, returns JSON
#                                        {shares, root_token}; one-time only
#   seal_submit_share <x:hex_y>        → accumulates a share; unseals at K
#   seal_seal                          → zeroes KEK; returns to sealed state
#   seal_is_sealed                     → 0 if sealed, 1 if unsealed
#   seal_is_initialized                → 0 if init has happened, 1 otherwise
#   seal_status                        → JSON {sealed, initialized, progress}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SHAMIR_PY="${SCRIPT_DIR}/shamir.py"

# ── module state ──────────────────────────────────────────────────────────────
# All in-memory. Wiped on process restart (cluster boots sealed by design).

_SEALED=true
_INITIALIZED=false
_SHARES_COLLECTED=()      # collected x:hex_y strings; zeroed after reconstruct
_SHARES_REQUIRED=0        # K from config.yaml
_SHARES_TOTAL=0           # N from config.yaml
_ROOT_TOKEN=""            # set once at init; consumed by auth.sh on first login

# State-mutating functions write JSON responses HERE rather than to stdout.
# Bash command substitution `$()` forks a subshell, so any module state set
# inside the function would be lost. Callers (HTTP handlers) read this
# variable after invoking the function.
_SEAL_RESPONSE=""

# ── initialisation ────────────────────────────────────────────────────────────

seal_init() {
  # Called by bin/strongbox on boot. Loads thresholds from config.yaml.
  # Does NOT generate the KEK — that happens in seal_init_cluster on /sys/init.
  _SEALED=true
  _INITIALIZED=false
  _SHARES_COLLECTED=()
  _ROOT_TOKEN=""

  local config_file="${SCRIPT_DIR}/../config.yaml"
  if [ ! -f "${config_file}" ]; then
    echo "error: config.yaml not found at ${config_file}" >&2
    return 1
  fi

  # Parse shamir.threshold and shamir.shares from a flat grep — the config
  # is intentionally simple key:value YAML, no nested parser needed.
  _SHARES_REQUIRED="$(awk '/^shamir:/{f=1;next} f && /threshold:/{print $2; exit}' "${config_file}")"
  _SHARES_TOTAL="$(awk    '/^shamir:/{f=1;next} f && /shares:/{print $2; exit}' "${config_file}")"

  # Sanity-check the values.
  if [ -z "${_SHARES_REQUIRED}" ] || [ -z "${_SHARES_TOTAL}" ]; then
    echo "error: shamir.threshold or shamir.shares missing from config.yaml" >&2
    return 1
  fi
  if [ "${_SHARES_REQUIRED}" -lt 2 ] || [ "${_SHARES_REQUIRED}" -gt "${_SHARES_TOTAL}" ]; then
    echo "error: invalid shamir config: K=${_SHARES_REQUIRED} N=${_SHARES_TOTAL}" >&2
    return 1
  fi
}

# ── cluster initialisation (POST /v1/sys/init) ────────────────────────────────

seal_init_cluster() {
  # One-time bootstrap. Generates the KEK pair, splits into N shares,
  # generates a root token, and writes the JSON response into _SEAL_RESPONSE.
  # The cluster remains SEALED — the operator must now submit K shares to unseal.
  #
  # IMPORTANT: callers must NOT capture stdout via $() — that forks a subshell
  # and the _INITIALIZED state mutation would be lost. Read _SEAL_RESPONSE.

  _SEAL_RESPONSE=""

  if ${_INITIALIZED}; then
    _SEAL_RESPONSE='{"error":"already initialized"}'
    return 1
  fi

  # Generate the KEK pair via crypto_gen_kek. Returns "enc_hex mac_hex".
  local kek_pair enc_key hmac_key
  kek_pair="$(crypto_gen_kek)"
  enc_key="${kek_pair%% *}"
  hmac_key="${kek_pair##* }"

  # Build the bundle: 128 hex chars = 64 raw bytes. This is the Shamir secret.
  local bundle_hex="${enc_key}${hmac_key}"

  # Split via shamir.py. The hex secret is piped on stdin — never argv.
  local shares_output
  shares_output="$(printf '%s\n' "${bundle_hex}" \
    | python3 "${SHAMIR_PY}" split "${_SHARES_REQUIRED}" "${_SHARES_TOTAL}")"

  if [ -z "${shares_output}" ]; then
    echo '{"error":"shamir split produced no output"}' >&2; return 1
  fi

  # Generate the root token. 32 bytes from CSPRNG, hex-encoded.
  _ROOT_TOKEN="$(openssl rand -hex 32)"

  # Build the JSON response. Each share line: "x:hexbytes"
  local shares_json="[" first=true line
  while IFS= read -r line; do
    [ -z "${line}" ] && continue
    if ${first}; then first=false; else shares_json="${shares_json},"; fi
    shares_json="${shares_json}\"${line}\""
  done <<< "${shares_output}"
  shares_json="${shares_json}]"

  # Zero all sensitive locals BEFORE returning the response.
  # We overwrite with zeroes first, then clear — Bash best-effort.
  local zero
  zero="$(head -c "${#bundle_hex}" /dev/zero | tr '\0' '0')"
  bundle_hex="${zero}"
  bundle_hex=""

  zero="$(head -c "${#enc_key}" /dev/zero | tr '\0' '0')"
  enc_key="${zero}"
  enc_key=""

  zero="$(head -c "${#hmac_key}" /dev/zero | tr '\0' '0')"
  hmac_key="${zero}"
  hmac_key=""

  zero="$(head -c "${#kek_pair}" /dev/zero | tr '\0' '0')"
  kek_pair="${zero}"
  kek_pair=""

  # The shares_output local STILL contains share data. Zero it.
  # The caller (HTTP handler) gets the JSON, not shares_output.
  zero="$(head -c "${#shares_output}" /dev/zero | tr '\0' '0')"
  shares_output="${zero}"
  shares_output=""

  _INITIALIZED=true

  # Write the response. Callers read _SEAL_RESPONSE, not our stdout.
  _SEAL_RESPONSE="$(printf '{"shares":%s,"root_token":"%s"}' "${shares_json}" "${_ROOT_TOKEN}")"
}

# ── share submission (POST /v1/sys/unseal) ────────────────────────────────────

seal_submit_share() {
  # Accepts one share. Writes JSON response into _SEAL_RESPONSE.
  # Callers must NOT capture via $() — share accumulation would be lost.
  local share="${1:-}"
  _SEAL_RESPONSE=""

  if ! ${_INITIALIZED}; then
    _SEAL_RESPONSE='{"error":"vault is not initialized — call /sys/init first"}'
    return 1
  fi

  if ! ${_SEALED}; then
    _SEAL_RESPONSE='{"error":"vault is already unsealed"}'
    return 1
  fi

  # Validate share format: <integer>:<hex>
  if ! echo "${share}" | grep -qE '^[0-9]+:[0-9a-f]+$'; then
    _SEAL_RESPONSE='{"error":"malformed share — expected format x:hexbytes"}'
    return 1
  fi

  # Reject duplicate share submissions.
  local existing
  for existing in "${_SHARES_COLLECTED[@]}"; do
    if [ "${existing}" = "${share}" ]; then
      local progress="${#_SHARES_COLLECTED[@]}"
      _SEAL_RESPONSE="$(printf '{"error":"duplicate share","sealed":true,"progress":"%d/%d"}' \
        "${progress}" "${_SHARES_REQUIRED}")"
      return 1
    fi
  done

  _SHARES_COLLECTED+=("${share}")
  local progress="${#_SHARES_COLLECTED[@]}"

  if [ "${progress}" -ge "${_SHARES_REQUIRED}" ]; then
    _seal_reconstruct_and_unseal
  else
    _SEAL_RESPONSE="$(printf '{"sealed":true,"progress":"%d/%d"}' \
      "${progress}" "${_SHARES_REQUIRED}")"
  fi
}

# ── reconstruction (internal) ─────────────────────────────────────────────────

_seal_reconstruct_and_unseal() {
  # Reconstruct the KEK bundle from collected shares, hand to crypto.sh,
  # zero everything sensitive in this stack frame.

  # Shares go to shamir.py via stdin — never argv.
  # /proc/PID/cmdline must never contain a share value.
  local bundle_hex
  bundle_hex="$(printf '%s\n' "${_SHARES_COLLECTED[@]}" \
    | python3 "${SHAMIR_PY}" reconstruct 2>/dev/null)" || {
    # Reconstruction failed. Zero collected shares and stay sealed.
    _zero_collected_shares
    _SEAL_RESPONSE='{"error":"reconstruction failed — invalid or corrupt shares"}'
    return 1
  }

  # Validate bundle length: 128 hex chars = 64 bytes.
  if [ "${#bundle_hex}" -ne 128 ]; then
    _zero_collected_shares
    local zero
    zero="$(head -c "${#bundle_hex}" /dev/zero | tr '\0' '0')"
    bundle_hex="${zero}"; bundle_hex=""
    _SEAL_RESPONSE='{"error":"reconstructed bundle has invalid length"}'
    return 1
  fi

  # Unbundle into the two halves.
  local enc_key="${bundle_hex:0:64}"
  local hmac_key="${bundle_hex:64:64}"

  # Load into crypto.sh BEFORE flipping state — if set_kek fails, stay sealed.
  crypto_set_kek "${enc_key}" "${hmac_key}"

  # ── ZERO EVERYTHING ───────────────────────────────────────────────────────
  # Bash best-effort: overwrite-then-clear each variable.

  # 1. Zero the reconstructed bundle.
  local zero
  zero="$(head -c "${#bundle_hex}" /dev/zero | tr '\0' '0')"
  bundle_hex="${zero}"
  bundle_hex=""

  # 2. Zero the unbundled key halves — crypto.sh now holds the canonical copy.
  zero="$(head -c "${#enc_key}" /dev/zero | tr '\0' '0')"
  enc_key="${zero}"; enc_key=""

  zero="$(head -c "${#hmac_key}" /dev/zero | tr '\0' '0')"
  hmac_key="${zero}"; hmac_key=""

  # 3. Zero every collected share and clear the array.
  _zero_collected_shares

  # Flip state to unsealed only AFTER all zeroing is complete.
  _SEALED=false

  _SEAL_RESPONSE="$(printf '{"sealed":false,"progress":"%d/%d"}' \
    "${_SHARES_REQUIRED}" "${_SHARES_REQUIRED}")"
}

_zero_collected_shares() {
  # Helper: overwrite every share with zeroes, then clear the array.
  local i
  for i in "${!_SHARES_COLLECTED[@]}"; do
    local len="${#_SHARES_COLLECTED[$i]}"
    _SHARES_COLLECTED[$i]="$(head -c "${len}" /dev/zero | tr '\0' '0')"
    unset '_SHARES_COLLECTED[$i]'
  done
  _SHARES_COLLECTED=()
}

# ── seal (POST /v1/sys/seal) ──────────────────────────────────────────────────

seal_seal() {
  crypto_clear_kek
  _zero_collected_shares
  _SEALED=true
  # Note: _INITIALIZED stays true. The vault remembers it was set up.
  # Operators re-unseal with the same shares they were given at init.
}

# ── status queries ────────────────────────────────────────────────────────────

seal_is_sealed() {
  ${_SEALED} && return 0 || return 1
}

seal_is_initialized() {
  ${_INITIALIZED} && return 0 || return 1
}

seal_status() {
  local progress="${#_SHARES_COLLECTED[@]}"
  local sealed_str initialized_str
  ${_SEALED}        && sealed_str=true      || sealed_str=false
  ${_INITIALIZED}   && initialized_str=true || initialized_str=false

  if ${_SEALED}; then
    printf '{"sealed":%s,"initialized":%s,"progress":"%d/%d","threshold":%d,"shares":%d}' \
      "${sealed_str}" "${initialized_str}" \
      "${progress}" "${_SHARES_REQUIRED}" \
      "${_SHARES_REQUIRED}" "${_SHARES_TOTAL}"
  else
    printf '{"sealed":%s,"initialized":%s,"progress":"%d/%d","threshold":%d,"shares":%d}' \
      "${sealed_str}" "${initialized_str}" \
      "${_SHARES_REQUIRED}" "${_SHARES_REQUIRED}" \
      "${_SHARES_REQUIRED}" "${_SHARES_TOTAL}"
  fi
}

# ── root token accessor (consumed by auth.sh on first use) ────────────────────

seal_get_root_token() {
  # Returns the root token generated at init. After auth.sh consumes it
  # (creates the bootstrap root user), this can be cleared.
  echo "${_ROOT_TOKEN}"
}

seal_clear_root_token() {
  # Called by auth.sh after the root token has been bound to a user.
  # The token itself remains valid — this just removes the bootstrap value
  # from seal.sh's memory.
  local zero
  zero="$(head -c "${#_ROOT_TOKEN}" /dev/zero | tr '\0' '0')"
  _ROOT_TOKEN="${zero}"
  _ROOT_TOKEN=""
}
