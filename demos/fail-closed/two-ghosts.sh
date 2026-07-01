#!/usr/bin/env bash
# Tier S #4 — two builds in the same policy class; both mint; origin can't link instances.
set -euo pipefail

DEMO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=_simulate.sh
source "$(dirname "$0")/_simulate.sh"
POLICY="$DEMO/fixtures/uqaz1-live-policy.json"

echo "=== Tier S: two ghosts, one policy class ==="
echo "Two different launch measurements, same class label — both pass appraisal."
echo "After PoMFRIT mint + spend, the origin sees two unlinkable tokens (not two identities)."
echo "PAT gives unlinkability only — not hardware build class + coupled binding."
echo

echo "--- ghost A (live uqaz1 measurement) ---"
simulate_policy "$POLICY" "$DEMO/fixtures/claims-good-build.json" | grep -E '"pass"|class_label|measurement'
echo

echo "--- ghost B (second allowed build in same class) ---"
simulate_policy "$POLICY" "$DEMO/fixtures/claims-ghost-b.json" | grep -E '"pass"|class_label|measurement'
echo

echo "Both pass → two FAEST authorizations → two PoMFRIT tokens → origin cannot tell same VM twice vs two VMs."
echo "Demo OK."
