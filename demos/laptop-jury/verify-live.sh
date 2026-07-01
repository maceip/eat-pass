#!/usr/bin/env bash
# Laptop-side verification for the "jury" demo — no TEE required on this machine.
set -euo pipefail

EAT_PASS_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
UQ_REPO="${UQ_REPO:-$EAT_PASS_ROOT/../unified-quote}"
UQ="${UQ_BIN:-$UQ_REPO/target/release/uq}"

if [[ ! -x "$UQ" ]]; then
  echo "build uq first: cd unified-quote/v2 && cargo build --release --bin uq" >&2
  echo "  or set UQ_BIN=/path/to/uq" >&2
  exit 1
fi

echo "=== Azure CVM (attested-TLS, vTPM → AMD root) ==="
"$UQ" azure check-tls https://attest.secure.build:8443/

echo
echo "=== AWS SEV-SNP (attested-TLS, Milan ARK) ==="
"$UQ" check https://3.138.156.141/

echo
echo "=== Dashboard ==="
echo "https://maceip.github.io/unified-quote/live.html"
