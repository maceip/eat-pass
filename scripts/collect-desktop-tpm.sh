#!/usr/bin/env bash
# Collect a Linux desktop TPM2 client attestation bundle for eat-pass.
#
# Produces an IMA-verified bundle when the kernel IMA log is available: the AK
# quote covers PCR 0-10, and the bundle carries the reported PCR values plus the
# IMA ascii_runtime_measurements log. The verifier
# (unified_quote::tee::desktop::tpm) then proves the agent binary was measured
# by the kernel into PCR 10 (not merely self-reported). Without a readable IMA
# log it falls back to a channel-bound-only bundle (weaker tier).
#
# Requires: tpm2-tools, openssl, python3.
# IMA mode additionally needs a sha256 IMA template:
#   ima_template=ima-ng ima_hash=sha256   (kernel cmdline)
# and a readable /sys/kernel/security/ima/ascii_runtime_measurements (root).
#
# Usage:
#   BINDING=<64-hex> BUILD_DIGEST=<64-hex> ./scripts/collect-desktop-tpm.sh [-o bundle.json]
#
# BINDING is the eat-pass channel binding (binding_of(blinded)).
# BUILD_DIGEST is sha256(agent binary) hex; it MUST be what IMA measured for the
# running binary. Policy allowlists desktop_build_id_hash(build_digest).

set -euo pipefail

OUT="desktop-tpm-bundle.json"
if [[ "${1:-}" == "-o" ]]; then
  OUT="${2:?missing -o path}"
elif [[ -n "${1:-}" ]]; then
  OUT="$1"
fi

BINDING="${BINDING:?set BINDING to 32-byte hex (eat-pass channel binding)}"
BUILD_DIGEST="${BUILD_DIGEST:?set BUILD_DIGEST to sha256(agent binary) hex}"

for cmd in tpm2_createek tpm2_createak tpm2_quote tpm2_pcrread tpm2_readpublic openssl python3; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd (install tpm2-tools/openssl)" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ek_ctx="$WORKDIR/ek.ctx"
ak_ctx="$WORKDIR/ak.ctx"
ek_pub="$WORKDIR/ek.pub"
ak_pub_pem="$WORKDIR/ak.pem"
ak_cert="$WORKDIR/ak.der"
tmp_key="$WORKDIR/tmp.key"
quote_msg="$WORKDIR/quote.msg"
quote_sig="$WORKDIR/quote.sig"
pcr_out="$WORKDIR/pcr.bin"
pcrread="$WORKDIR/pcrread.txt"
ima_log="$WORKDIR/ima.log"

# Endorsement key + an ECDSA(P-256)/sha256 Attestation Key under it.
tpm2_createek -c "$ek_ctx" -G rsa -u "$ek_pub" >/dev/null 2>&1
tpm2_createak -C "$ek_ctx" -c "$ak_ctx" -G ecc -g sha256 -s ecdsa \
  -u "$WORKDIR/ak.tpmpub" -n "$WORKDIR/ak.name" >/dev/null 2>&1

# Quote PCR 0-10 (sha256), binding the channel binding into extraData.
PCR_LIST="sha256:0,1,2,3,4,5,6,7,8,9,10"
tpm2_quote -c "$ak_ctx" -l "$PCR_LIST" -q "$BINDING" \
  -m "$quote_msg" -s "$quote_sig" -o "$pcr_out" -g sha256 >/dev/null 2>&1
tpm2_pcrread "$PCR_LIST" > "$pcrread" 2>/dev/null

# Build an X.509 cert whose SPKI is the AK public key. The verifier reads the
# SPKI to check the quote signature; it does not validate this cert's own
# signature, so a throwaway issuer key is fine. (AK->EK->manufacturer-root
# attestation via credential activation is a documented follow-on.)
tpm2_readpublic -c "$ak_ctx" -f pem -o "$ak_pub_pem" >/dev/null 2>&1
openssl ecparam -genkey -name prime256v1 -out "$tmp_key" >/dev/null 2>&1
openssl req -new -x509 -key "$tmp_key" -subj "/CN=eat-pass-ak" \
  -force_pubkey "$ak_pub_pem" -days 1 -outform der -out "$ak_cert" >/dev/null 2>&1

# IMA measurement log (optional; enables the hardware-measured-binary path).
IMA_SRC="/sys/kernel/security/ima/ascii_runtime_measurements"
if [[ -r "$IMA_SRC" ]]; then
  cat "$IMA_SRC" > "$ima_log"
else
  : > "$ima_log"
  echo "warning: $IMA_SRC not readable; emitting channel-bound-only bundle (run as root with IMA enabled for the stronger tier)" >&2
fi

PLATFORM="linux-tpm-client"
case "$(uname -s)" in MINGW* | *NT*) PLATFORM="windows-tpm-client" ;; esac

OUT="$OUT" PLATFORM="$PLATFORM" BINDING="$BINDING" BUILD_DIGEST="$BUILD_DIGEST" \
AK_CERT="$ak_cert" QUOTE_MSG="$quote_msg" QUOTE_SIG="$quote_sig" \
PCRREAD="$pcrread" IMA_LOG="$ima_log" \
python3 - <<'PY'
import json, os, pathlib, re

def hexfile(p):
    return pathlib.Path(p).read_bytes().hex()

# Parse `tpm2_pcrread sha256:...` output: lines like "    10: 0xABCD...".
pcrs = []
for line in pathlib.Path(os.environ["PCRREAD"]).read_text().splitlines():
    m = re.match(r"\s*(\d+)\s*:\s*0x([0-9A-Fa-f]+)\s*$", line)
    if m:
        pcrs.append({"index": int(m.group(1)), "value": m.group(2).lower()})

ima = pathlib.Path(os.environ["IMA_LOG"]).read_text()

data = {
    "version": 1,
    "platform": os.environ["PLATFORM"],
    "binding": os.environ["BINDING"],
    "build_digest": os.environ["BUILD_DIGEST"],
    "ak_cert": hexfile(os.environ["AK_CERT"]),
    "quote_msg": hexfile(os.environ["QUOTE_MSG"]),
    "quote_sig": hexfile(os.environ["QUOTE_SIG"]),
    "qualifying_data": os.environ["BINDING"],
}
# Only include the IMA-mode fields together (the verifier requires both).
if ima.strip() and pcrs:
    data["pcr_bank"] = "sha256"
    data["pcrs"] = pcrs
    data["ima_log"] = ima

out = pathlib.Path(os.environ["OUT"])
out.write_text(json.dumps(data, indent=2) + "\n")
print(out)
PY

echo "wrote $OUT" >&2
