#!/usr/bin/env bash
# lib/consensus.sh — hand-rolled Raft-inspired leader election
#
# Election loop runs in the parent bin/strongbox process only.
# Each ncat handler reads/writes state from _CS_DIR files.
# node-1 bootstraps as leader (term 1).

set -euo pipefail

_NODE_ID="${STRONGBOX_NODE_ID:-node-1}"
_PEERS=()
_ELECTION_TIMEOUT_MIN_MS=500
_ELECTION_TIMEOUT_MAX_MS=1000
_CS_DIR="${_CS_DIR:-/dev/shm/strongbox/consensus}"

_now_ms() { date +%s%3N; }

consensus_init() {
  mkdir -p "${_CS_DIR}"
  if [[ ! -f "${_CS_DIR}/role" ]]; then
    if [[ "${_NODE_ID}" == "node-1" ]]; then
      echo "leader" > "${_CS_DIR}/role"
      echo "${_NODE_ID}" > "${_CS_DIR}/leader"
      echo "1" > "${_CS_DIR}/term"
    else
      echo "follower" > "${_CS_DIR}/role"
      echo "node-1" > "${_CS_DIR}/leader"
      echo "0" > "${_CS_DIR}/term"
    fi
  fi
  [[ -f "${_CS_DIR}/voted_for" ]] || echo "" > "${_CS_DIR}/voted_for"
  [[ -f "${_CS_DIR}/last_hb" ]]   || _now_ms > "${_CS_DIR}/last_hb"
  IFS=' ' read -ra _PEERS <<< "${STRONGBOX_PEERS:-}"
  export _CS_DIR _NODE_ID
}

_cs_read()  { cat "${_CS_DIR}/${1}" 2>/dev/null; }
_cs_write() { printf '%s' "${2}" > "${_CS_DIR}/${1}"; }

consensus_is_leader()      { [[ "$(_cs_read role)" == "leader" ]]; }
consensus_leader_hint()    { _cs_read leader; }
_consensus_read_term()     { _cs_read term; }

consensus_quorum_reachable() {
  IFS=' ' read -ra _PEERS <<< "${STRONGBOX_PEERS:-}"
  local reachable=1
  for peer in "${_PEERS[@]}"; do
    [[ -z "${peer}" ]] && continue
    curl -sf --max-time 0.2 "${peer}/v1/sys/health" >/dev/null 2>&1 && reachable=$(( reachable + 1 ))
  done
  local total=$(( ${#_PEERS[@]} + 1 ))
  [[ "${reachable}" -ge $(( total / 2 + 1 )) ]]
}

_consensus_election_loop() {
  IFS=' ' read -ra _PEERS <<< "${STRONGBOX_PEERS:-}"

  if [[ "$(_cs_read role)" == "leader" ]]; then
    sleep 0.5; _consensus_send_heartbeats; sleep 0.1; _consensus_send_heartbeats
  fi

  while true; do
    local range=$(( _ELECTION_TIMEOUT_MAX_MS - _ELECTION_TIMEOUT_MIN_MS ))
    local tms=$(( (RANDOM % range) + _ELECTION_TIMEOUT_MIN_MS ))
    sleep "$(echo "scale=3; ${tms}/1000" | bc)"

    if [[ "$(_cs_read role)" == "leader" ]]; then
      _consensus_send_heartbeats
    else
      local now last_hb; now="$(_now_ms)"; last_hb="$(_cs_read last_hb)"; last_hb="${last_hb:-0}"
      if (( now - last_hb >= tms )); then _consensus_start_election; fi
    fi
  done
}

_consensus_start_election() {
  _cs_write role "candidate"
  local new_term=$(( $(_cs_read term) + 1 ))
  _cs_write term "${new_term}"; _cs_write voted_for "${_NODE_ID}"
  local votes=1 total=$(( ${#_PEERS[@]} + 1 )) quorum=$(( (${#_PEERS[@]} + 1) / 2 + 1 ))

  for peer in "${_PEERS[@]}"; do
    [[ -z "${peer}" ]] && continue
    local resp; resp="$(curl -sf --max-time 0.5 -X POST "${peer}/internal/vote" \
      -H 'Content-Type: application/json' \
      -d "$(printf '{"term":%d,"candidate_id":"%s"}' "${new_term}" "${_NODE_ID}")" 2>/dev/null)" || continue
    [[ "$(echo "${resp}" | grep -o '"granted":[a-z]*' | cut -d: -f2)" == "true" ]] && votes=$(( votes + 1 ))
  done

  if (( votes >= quorum )); then
    _cs_write role "leader"; _cs_write leader "${_NODE_ID}"; _consensus_send_heartbeats
  else
    _cs_write role "follower"
  fi
}

_consensus_send_heartbeats() {
  local term; term="$(_cs_read term)"
  for peer in "${_PEERS[@]}"; do
    [[ -z "${peer}" ]] && continue
    curl -sf --max-time 0.1 -X POST "${peer}/internal/heartbeat" \
      -H 'Content-Type: application/json' \
      -d "$(printf '{"term":%d,"leader_id":"%s"}' "${term}" "${_NODE_ID}")" \
      >/dev/null 2>&1 &
  done
}

_CONSENSUS_RESPONSE=""

consensus_handle_vote() {
  local req="$1"
  local term; term="$(echo "${req}" | grep -o '"term":[0-9]*' | cut -d: -f2)"
  local cid; cid="$(echo "${req}" | grep -o '"candidate_id":"[^"]*"' | cut -d\" -f4)"
  local cur; cur="$(_cs_read term)"
  local vf; vf="$(_cs_read voted_for)"
  local granted=false

  if (( term > cur )) && { [[ -z "${vf}" ]] || [[ "${vf}" == "${cid}" ]]; }; then
    _cs_write term "${term}"; _cs_write voted_for "${cid}"; _cs_write role "follower"
    _now_ms > "${_CS_DIR}/last_hb"; granted=true
  fi
  _CONSENSUS_RESPONSE="$(printf '{"term":%d,"granted":%s}' "$(_cs_read term)" "${granted}")"
}

consensus_handle_hb() {
  local req="$1"
  local term; term="$(echo "${req}" | grep -o '"term":[0-9]*' | cut -d: -f2)"
  local lid; lid="$(echo "${req}" | grep -o '"leader_id":"[^"]*"' | cut -d\" -f4)"
  local cur; cur="$(_cs_read term)"

  if (( term >= cur )); then
    _cs_write term "${term}"; _cs_write leader "${lid}"
    _cs_write role "follower"; _cs_write voted_for ""
    _now_ms > "${_CS_DIR}/last_hb"
  fi
  _CONSENSUS_RESPONSE="$(printf '{"term":%d,"node_id":"%s","ack":true}' "$(_cs_read term)" "${_NODE_ID}")"
}
