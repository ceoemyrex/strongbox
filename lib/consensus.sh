#!/usr/bin/env bash
# lib/consensus.sh — hand-rolled leader election (Raft-inspired)
#
# Implements: term numbers, randomised election timeouts, vote granting,
# leader heartbeats, minority partition guard.
#
# Rules:
#   - A node starts as follower with term 0.
#   - If no heartbeat arrives within a randomised timeout, it becomes
#     a candidate, increments its term, and requests votes from peers.
#   - A node grants a vote to at most one candidate per term.
#   - A candidate that receives votes from a strict majority becomes leader.
#   - The leader sends heartbeats every HEARTBEAT_INTERVAL to reset follower timers.
#   - Writes are accepted by the leader only; followers reject writes and
#     return a leader hint so clients can retry against the right node.
#   - A node that cannot reach a majority of peers refuses writes (partition guard).
#
# No external raft library is used. All election logic is in this file.
#
# Public interface:
#   consensus_init           → starts election timer background loop
#   consensus_is_leader      → 0 if this node is leader, 1 otherwise
#   consensus_leader_hint    → prints current leader node_id (may be empty)
#   consensus_quorum_reachable → 0 if majority of peers reachable, 1 otherwise
#   consensus_handle_vote    <request_json>    → vote response JSON
#   consensus_handle_hb      <heartbeat_json>  → ack JSON

set -euo pipefail

_NODE_ID="${STRONGBOX_NODE_ID:-node-1}"
_CURRENT_TERM=0
_VOTED_FOR=""
_ROLE="follower"
_CURRENT_LEADER=""
_LAST_HEARTBEAT_MS=0

# Loaded from config.yaml.
_ELECTION_TIMEOUT_MIN_MS=150
_ELECTION_TIMEOUT_MAX_MS=300
_HEARTBEAT_INTERVAL_MS=50
_PEERS=()   # e.g. ("http://strongbox-node-2:8200" "http://strongbox-node-3:8200")

consensus_init() {
  _LAST_HEARTBEAT_MS="$(_now_ms)"
  _consensus_load_peers
  _consensus_election_loop &
  disown
}

_consensus_load_peers() {
  # TODO: parse cluster.peers from config.yaml.
  # For now peers come from STRONGBOX_PEERS env var (space-separated URLs).
  IFS=' ' read -ra _PEERS <<< "${STRONGBOX_PEERS:-}"
}

_now_ms() {
  date +%s%3N
}

consensus_is_leader() {
  [[ "${_ROLE}" == "leader" ]] && return 0 || return 1
}

consensus_leader_hint() {
  echo "${_CURRENT_LEADER}"
}

consensus_quorum_reachable() {
  local reachable=1  # count self
  local peer
  for peer in "${_PEERS[@]}"; do
    curl -sf --max-time 0.1 "${peer}/v1/sys/health" >/dev/null 2>&1 && \
      reachable=$(( reachable + 1 ))
  done
  local total=$(( ${#_PEERS[@]} + 1 ))
  local quorum=$(( total / 2 + 1 ))
  [[ "${reachable}" -ge "${quorum}" ]] && return 0 || return 1
}

_consensus_election_loop() {
  while true; do
    # Randomised timeout in the range [MIN, MAX].
    local range=$(( _ELECTION_TIMEOUT_MAX_MS - _ELECTION_TIMEOUT_MIN_MS ))
    local timeout_ms=$(( (RANDOM % range) + _ELECTION_TIMEOUT_MIN_MS ))
    sleep "$(echo "scale=3; ${timeout_ms}/1000" | bc)"

    if [[ "${_ROLE}" == "leader" ]]; then
      _consensus_send_heartbeats
    else
      local now; now="$(_now_ms)"
      local elapsed=$(( now - _LAST_HEARTBEAT_MS ))
      if [[ "${elapsed}" -ge "${timeout_ms}" ]]; then
        _consensus_start_election
      fi
    fi
  done
}

_consensus_start_election() {
  _ROLE="candidate"
  _CURRENT_TERM=$(( _CURRENT_TERM + 1 ))
  _VOTED_FOR="${_NODE_ID}"
  local votes=1  # vote for self

  local total=$(( ${#_PEERS[@]} + 1 ))
  local quorum=$(( total / 2 + 1 ))

  local peer response granted
  for peer in "${_PEERS[@]}"; do
    response="$(curl -sf --max-time 0.1 -X POST \
      "${peer}/internal/vote" \
      -H 'Content-Type: application/json' \
      -d "$(printf '{"term":%d,"candidate_id":"%s"}' \
            "${_CURRENT_TERM}" "${_NODE_ID}")" 2>/dev/null)" || continue

    granted="$(echo "${response}" | grep -o '"granted":[a-z]*' | cut -d: -f2)"
    [[ "${granted}" == "true" ]] && votes=$(( votes + 1 ))
  done

  if [[ "${votes}" -ge "${quorum}" ]]; then
    _ROLE="leader"
    _CURRENT_LEADER="${_NODE_ID}"
    _consensus_send_heartbeats
  else
    # Split vote or no quorum — revert to follower; election loop will retry.
    _ROLE="follower"
  fi
}

_consensus_send_heartbeats() {
  local peer
  for peer in "${_PEERS[@]}"; do
    curl -sf --max-time 0.05 -X POST \
      "${peer}/internal/heartbeat" \
      -H 'Content-Type: application/json' \
      -d "$(printf '{"term":%d,"leader_id":"%s"}' \
            "${_CURRENT_TERM}" "${_NODE_ID}")" \
      >/dev/null 2>&1 &
  done
}

consensus_handle_vote() {
  local req="${1}"
  local term candidate_id
  term="$(echo "${req}"         | grep -o '"term":[0-9]*'          | cut -d: -f2)"
  candidate_id="$(echo "${req}" | grep -o '"candidate_id":"[^"]*"' | cut -d\" -f4)"

  local granted=false
  if [[ "${term}" -gt "${_CURRENT_TERM}" ]] && \
     { [[ -z "${_VOTED_FOR}" ]] || [[ "${_VOTED_FOR}" == "${candidate_id}" ]]; }; then
    _CURRENT_TERM="${term}"
    _VOTED_FOR="${candidate_id}"
    _ROLE="follower"
    _LAST_HEARTBEAT_MS="$(_now_ms)"
    granted=true
  fi

  printf '{"term":%d,"granted":%s}' "${_CURRENT_TERM}" "${granted}"
}

consensus_handle_hb() {
  local req="${1}"
  local term leader_id
  term="$(echo "${req}"      | grep -o '"term":[0-9]*'        | cut -d: -f2)"
  leader_id="$(echo "${req}" | grep -o '"leader_id":"[^"]*"'  | cut -d\" -f4)"

  if [[ "${term}" -ge "${_CURRENT_TERM}" ]]; then
    _CURRENT_TERM="${term}"
    _CURRENT_LEADER="${leader_id}"
    _ROLE="follower"
    _VOTED_FOR=""
    _LAST_HEARTBEAT_MS="$(_now_ms)"
  fi

  printf '{"term":%d,"node_id":"%s","ack":true}' "${_CURRENT_TERM}" "${_NODE_ID}"
}
