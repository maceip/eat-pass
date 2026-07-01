#!/usr/bin/env bash
set -euo pipefail

EXPECTED_REV="fb4bb069528b1a5d586c10332693334e48e76a1c"
STACK_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

repos=(
  "eat-pass"
  "attestation-service"
  "attested-workload"
  "cvm-agent"
)

failed=0
for repo in "${repos[@]}"; do
  lock="$STACK_ROOT/$repo/Cargo.lock"
  manifest="$STACK_ROOT/$repo/Cargo.toml"
  if [[ ! -f "$lock" ]]; then
    echo "missing lockfile: $lock" >&2
    failed=1
    continue
  fi
  if [[ ! -f "$manifest" ]]; then
    echo "missing manifest: $manifest" >&2
    failed=1
    continue
  fi

  if grep -R --include Cargo.toml -q 'github.com/maceip/unified-quote' "$STACK_ROOT/$repo"; then
    if ! grep -q "github.com/maceip/unified-quote?rev=$EXPECTED_REV#$EXPECTED_REV" "$lock"; then
      echo "$repo: Cargo.lock does not resolve unified-quote to $EXPECTED_REV" >&2
      failed=1
    fi
    if grep -R --include Cargo.toml -n 'github.com/maceip/unified-quote' "$STACK_ROOT/$repo" \
      | grep -v "rev = \"$EXPECTED_REV\"" >/dev/null; then
      echo "$repo: Cargo.toml has a unified-quote dependency not pinned to $EXPECTED_REV" >&2
      failed=1
    fi
  fi
done

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "unified-quote pin OK: $EXPECTED_REV"
