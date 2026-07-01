#!/usr/bin/env bash
# Run all eat-pass demos that can execute from a developer laptop (no CVM mint required).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PASS=0
FAIL=0
SKIP=0

run() {
  local name="$1"
  shift
  echo
  echo "════════════════════════════════════════════════════════"
  echo "TEST: $name"
  echo "════════════════════════════════════════════════════════"
  if "$@"; then
    echo ">>> PASS: $name"
    PASS=$((PASS + 1))
  else
    local rc=$?
    if [[ "$rc" -eq 2 ]]; then
      echo ">>> SKIP: $name (optional / offline)"
      SKIP=$((SKIP + 1))
    else
      echo ">>> FAIL: $name (exit $rc)"
      FAIL=$((FAIL + 1))
    fi
  fi
}

echo "eat-pass demo test suite"
echo "repo: $ROOT"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

run "policy JSON fixtures" bash -c '
  for f in policy/examples/*.json demos/fixtures/*.json; do
    python3 -c "import json; json.load(open(\"$f\"))" || exit 1
  done
'

run "policy_simulate self-test" python3 demos/fail-closed/test_policy_simulate.py

run "fail-closed run-all" demos/fail-closed/run-all.sh

run "laptop-jury verify-live" demos/laptop-jury/verify-live.sh

run "tool-gate show-no-proof (live uqaz1)" demos/tool-gate/show-no-proof.sh

run "attestation-service demo.sh" bash -c '
  AS="${ATTESTATION_SERVICE_REPO:-../attestation-service}"
  [[ -x "$AS/scripts/demo.sh" ]] || { echo "attestation-service not at $AS — skip"; exit 2; }
  bash "$AS/scripts/demo.sh" >/dev/null
'

run "tool-gate send-email happy (live uqaz1)" bash -c '
  [[ "${SKIP_LIVE_SEND:-}" == "1" ]] && { echo "SKIP_LIVE_SEND=1"; exit 2; }
  demos/tool-gate/send-email-happy.sh "test-all $(date -u +%Y%m%dT%H%M%SZ)"
'

run "unified-quote report_nodes (dry)" bash -c '
  UQ_REPO="${UQ_REPO:-../unified-quote}"
  UQ_BIN="${UQ_BIN:-$UQ_REPO/target/release/uq}"
  REPORT="$UQ_REPO/deploy/report_nodes.py"
  if [[ ! -f "$REPORT" ]]; then
    echo "unified-quote not present ($UQ_REPO) — skip"
    exit 2
  fi
  if [[ ! -x "$UQ_BIN" ]]; then
    echo "uq not built at $UQ_BIN — skip"
    exit 2
  fi
  ( cd "$UQ_REPO" && UQ_BIN="$UQ_BIN" python3 deploy/report_nodes.py ) | grep -q "azure-cvm-we: verified"
'

echo
echo "════════════════════════════════════════════════════════"
echo "SUMMARY: pass=$PASS fail=$FAIL skip=$SKIP"
echo "════════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
exit 0
