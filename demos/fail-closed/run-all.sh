#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
for s in wrong-binary.sh binding-or-bust.sh two-ghosts.sh; do
  echo "######## $s ########"
  bash "$DIR/$s"
  echo
done
