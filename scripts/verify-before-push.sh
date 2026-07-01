#!/usr/bin/env bash
# Run before pushing eat-pass: demo scripts + optional full workspace tests in Docker.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

RUN_DOCKER="${RUN_DOCKER:-0}"
REMOTE_TEST="${EAT_PASS_REMOTE:-azureuser@attest.secure.build}"
if [[ "${1:-}" == "--full" ]]; then
  RUN_DOCKER=1
  shift
fi

echo "=== verify-before-push ==="

bash scripts/verify-unified-quote-pin.sh
bash demos/test-all.sh

if [[ "$RUN_DOCKER" == "1" ]]; then
  if [[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]; then
    EAT_PASS_REMOTE="$REMOTE_TEST" bash scripts/test-workspace-linux-docker.sh
  else
    bash scripts/test-workspace-linux-docker.sh
  fi
else
  echo
  echo "Tip: ./scripts/verify-before-push.sh --full for cargo test --workspace"
  echo "     (on macOS ARM: runs on $REMOTE_TEST via SSH)"
fi

echo "=== verify-before-push OK ==="
