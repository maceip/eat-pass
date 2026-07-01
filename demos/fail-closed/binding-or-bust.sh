#!/usr/bin/env bash
# Tier S #3 — quote for binding₁ reused against binding₂ → reject (coupled mint).
set -euo pipefail

DEMO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=_simulate.sh
source "$(dirname "$0")/_simulate.sh"
POLICY="$DEMO/fixtures/uqaz1-live-policy.json"

echo "=== Tier S: binding or bust ==="
echo "Correct measurement but binding_ok=false simulates replaying evidence against a new blind request."
echo "PAT can't do this: no hardware-signed eat_nonce / AK qualifyingData tie."
echo

echo "--- binding matches mint request ---"
simulate_policy "$POLICY" "$DEMO/fixtures/claims-good-build.json"
echo "→ PASS"
echo

echo "--- binding mismatch (stale quote / wrong blind) ---"
set +e
simulate_policy "$POLICY" "$DEMO/fixtures/claims-wrong-binding.json" 2>/dev/null
RC=$?
set -e
if [[ "$RC" -eq 0 ]]; then
  echo "→ FAIL demo: expected rejection" >&2
  exit 1
fi
echo "→ REJECT (BindingOk failed — coupled mint blocks replay)"
echo
echo "Demo OK."
