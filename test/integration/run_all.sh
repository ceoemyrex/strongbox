#!/usr/bin/env bash
# test/integration/run_all.sh
# Runs all 10 grading scenarios in sequence. No manual intervention between them.
#
# Usage:
#   export STRONGBOX_URL=https://yourdomain.com
#   export STRONGBOX_ROOT_TOKEN=<root token from sys/init>
#   bash test/integration/run_all.sh
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOTAL=0
FAILED=0

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
