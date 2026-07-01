#!/usr/bin/env bash
# Run policy appraisal: prefer eat-pass CLI, fall back to Python mirror (no native PoMFRIT build).
simulate_policy() {
  local policy="$1"
  local claims="$2"
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  local eat="${EAT_PASS_BIN:-$root/target/release/eat-pass}"
  if [[ -x "$eat" ]] && "$eat" policy --help &>/dev/null; then
    "$eat" policy simulate --policy "$policy" --claims "$claims"
  else
    python3 "$(dirname "${BASH_SOURCE[0]}")/policy_simulate.py" "$policy" "$claims"
  fi
}
