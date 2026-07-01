#!/usr/bin/env bash
# Tier S #2 — wrong launch measurement → policy reject (before any PoMFRIT mint).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=_simulate.sh
source "$(dirname "$0")/_simulate.sh"
POLICY="$DEMO/fixtures/uqaz1-live-policy.json"

echo "=== Tier S: wrong binary dies at the gate ==="
echo "Policy allows uqaz1 launch measurement only (+ ghost B for another demo)."
echo "PAT can't do this: platform tokens don't allowlist silicon launch digests."
echo

echo "--- allowed build (uqaz1) ---"
simulate_policy "$POLICY" "$DEMO/fixtures/claims-good-build.json"
echo "→ PASS (attester would FAEST-sign authorization)"
echo

echo "--- wrong build (measurement not in allow) ---"
set +e
simulate_policy "$POLICY" "$DEMO/fixtures/claims-wrong-build.json" 2>/dev/null
RC=$?
set -e
if [[ "$RC" -eq 0 ]]; then
  echo "→ FAIL demo: expected rejection" >&2
  exit 1
fi
echo "→ REJECT (ReferenceValueMatch failed — no mint, no token)"
echo
echo "Demo OK."
