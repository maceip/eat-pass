#!/usr/bin/env bash
# Collect a Linux desktop TPM2 client attestation bundle for eat-pass.
# Requires: tpm2-tools, sha256sum, python3 (hex encode)
#
# Usage:
#   BINDING=<64-hex-chars> BUILD_DIGEST=<64-hex-chars> ./scripts/collect-desktop-tpm.sh [-o bundle.json]
#
# BUILD_DIGEST is sha256(agent binary) hex. Policy allowlist uses
# desktop_build_id_hash(build_digest) — compute with:
#   eat-pass desktop hash-build /path/to/agent

set -euo pipefail

OUT="${1:-desktop-tpm-bundle.json}"
if [[ "${1:-}" == "-o" ]]; then
  OUT="${2:?missing -o path}"
fi

BINDING="${BINDING:?set BINDING to 32-byte hex (eat-pass channel binding)}"
BUILD_DIGEST="${BUILD_DIGEST:?set BUILD_DIGEST to sha256(agent binary) hex}"

for cmd in tpm2_getcap tpm2_createek tpm2_createak tpm2_quote xxd python3; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd (install tpm2-tools)" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ctx="$WORKDIR/ctx"
ak_ctx="$WORKDIR/ak.ctx"
ek_pub="$WORKDIR/ek.pub"
ak_pub="$WORKDIR/ak.pub"
ak_name="$WORKDIR/ak.name"
ak_cert="$WORKDIR/ak.der"
quote_msg="$WORKDIR/quote.msg"
quote_sig="$WORKDIR/quote.sig"
pcrs="$WORKDIR/pcr.bin"

tpm2_createek -c "$ctx" -G rsa -u "$ek_pub" 2>/dev/null
tpm2_createak -C "$ctx" -c "$ak_ctx" -G ecc -g sha256 -s ecdsa \
  -u "$ak_pub" -n "$ak_name" 2>/dev/null

# PCR0 for boot/core (extend policy as needed).
echo "00000000" | xxd -r -p > "$pcrs"
tpm2_quote -c "$ak_ctx" -l sha256:0 -q "$quote_msg" -m "$quote_sig" -g sha256 \
  -L "$BINDING" -o "$pcrs" 2>/dev/null

# Self-signed AK cert placeholder: export public area as DER-ish for verifier AK parse.
# Production agents should use tpm2_activatecredential / EK-certified AK.
tpm2_readpublic -c "$ak_ctx" -o "$ak_cert" -f der 2>/dev/null || cp "$ak_pub" "$ak_cert"

hexfile() { python3 - "$1" <<'PY'
import sys, pathlib
print(pathlib.Path(sys.argv[1]).read_bytes().hex())
PY
}

PLATFORM="linux-tpm-client"
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == *NT* ]]; then
  PLATFORM="windows-tpm-client"
fi

python3 - "$OUT" <<PY
import json, pathlib, os
out = pathlib.Path("$OUT")
data = {
  "version": 1,
  "platform": "$PLATFORM",
  "binding": "$BINDING",
  "build_digest": "$BUILD_DIGEST",
  "ak_cert": "$(hexfile "$ak_cert")",
  "quote_msg": "$(hexfile "$quote_msg")",
  "quote_sig": "$(hexfile "$quote_sig")",
  "qualifying_data": "$BINDING",
}
out.write_text(json.dumps(data, indent=2) + "\n")
print(out)
PY

echo "wrote $OUT"
