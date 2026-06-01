#!/usr/bin/env bash
# Runs all integration scenarios in order. Each script is an independent grading scenario.
# STRONGBOX_ROOT_TOKEN is extracted from 00_init output and exported for subsequent tests.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL=0
FAILED=0

export STRONGBOX_URL="${STRONGBOX_URL:-http://localhost:8201}"

run() {
  local script="$1"
  TOTAL=$(( TOTAL + 1 ))
  echo ""
  if bash "${script}"; then
    echo "  ✓  $(basename "${script}" .sh)"
  else
    echo "  ✗  $(basename "${script}" .sh)"
    FAILED=$(( FAILED + 1 ))
  fi
}

run "${DIR}/00_init.sh"

# 00_init writes /tmp/sb_init.json; extract root_token so later scripts can authenticate
if [[ -f /tmp/sb_init.json ]]; then
  export STRONGBOX_ROOT_TOKEN="$(python3 -c "import json; print(json.load(open('/tmp/sb_init.json'))['root_token'])")"
fi

run "${DIR}/01_unseal.sh"
run "${DIR}/02_secrets.sh"
run "${DIR}/03_policy.sh"
run "${DIR}/04_revocation.sh"
run "${DIR}/05_dynamic_pg.sh"
run "${DIR}/06_pg_down.sh"
run "${DIR}/07_leader_kill.sh"
run "${DIR}/08_partition.sh"
run "${DIR}/09_audit_tamper.sh"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Results: $(( TOTAL - FAILED )) / ${TOTAL} scenarios passed"
[[ "${FAILED}" -eq 0 ]] || exit 1
