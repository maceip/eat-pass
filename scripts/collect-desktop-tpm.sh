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
# Requires: tpm2-tools, python3.
# IMA mode additionally needs a sha256 IMA template:
#   ima_template=ima-ng ima_hash=sha256   (kernel cmdline)
# and a readable /sys/kernel/security/ima/ascii_runtime_measurements (root).
#
# Usage:
#   BINDING=<64-hex> BUILD_DIGEST=<64-hex> \
#     TPM_AK_CTX=ak.ctx \
#     TPM_AK_NAME_FILE=ak.name \
#     AK_CERT_DER=ak.der \
#     EK_CERT_DER=ek.der \
#     EK_CA_CHAIN_DER="ek-intermediate.der:ek-root.der" \
#     TPM_CREDENTIAL_ACTIVATION_JSON=activation.json \
#     ./scripts/collect-desktop-tpm.sh [-o bundle.json]
#
# BINDING is the eat-pass channel binding (binding_of(blinded)).
# BUILD_DIGEST is sha256(agent binary) hex; it MUST be what IMA measured for the
# running binary. Policy allowlists desktop_build_id_hash(build_digest).
#
# EK_CERT_DER and EK_CA_CHAIN_DER are verifier trust inputs carried in the
# evidence bundle; policy must pin the final EK root fingerprint. The activation
# JSON must contain { "token": ..., "secret": "<hex>" } from a verifier-issued
# makecredential/activatecredential flow for this AK name, EK cert, AK cert, and
# binding. A self-signed AK certificate by itself is not TPM provenance.

set -euo pipefail

OUT="desktop-tpm-bundle.json"
if [[ "${1:-}" == "-o" ]]; then
  OUT="${2:?missing -o path}"
elif [[ -n "${1:-}" ]]; then
  OUT="$1"
fi

BINDING="${BINDING:?set BINDING to 32-byte hex (eat-pass channel binding)}"
BUILD_DIGEST="${BUILD_DIGEST:?set BUILD_DIGEST to sha256(agent binary) hex}"
EK_CERT_DER="${EK_CERT_DER:-}"
EK_CA_CHAIN_DER="${EK_CA_CHAIN_DER:-}"
TPM_CREDENTIAL_ACTIVATION_JSON="${TPM_CREDENTIAL_ACTIVATION_JSON:-}"
TPM_AK_CTX="${TPM_AK_CTX:-}"
TPM_AK_NAME_FILE="${TPM_AK_NAME_FILE:-}"
AK_CERT_DER="${AK_CERT_DER:-}"

if [[ -z "$TPM_AK_CTX" || -z "$TPM_AK_NAME_FILE" || -z "$AK_CERT_DER" || -z "$EK_CERT_DER" || -z "$EK_CA_CHAIN_DER" || -z "$TPM_CREDENTIAL_ACTIVATION_JSON" ]]; then
  cat >&2 <<'EOF'
missing hardened desktop TPM provenance inputs:
  TPM_AK_CTX                          persistent AK context used for activation
  TPM_AK_NAME_FILE                    TPM2B_NAME file for that AK
  AK_CERT_DER                         DER AK certificate bound by the activation token
  EK_CERT_DER                         DER EK certificate for this TPM
  EK_CA_CHAIN_DER                     colon-separated DER issuer chain ending at pinned root
  TPM_CREDENTIAL_ACTIVATION_JSON      verifier activation token + recovered secret

The old self-signed-AK-only bundle is intentionally not emitted. Provision a
persistent AK, run EK-rooted credential activation for that AK/cert/name first,
then rerun this collector.
EOF
  exit 2
fi
[[ -r "$TPM_AK_CTX" ]] || { echo "TPM_AK_CTX not readable: $TPM_AK_CTX" >&2; exit 2; }
[[ -r "$TPM_AK_NAME_FILE" ]] || { echo "TPM_AK_NAME_FILE not readable: $TPM_AK_NAME_FILE" >&2; exit 2; }
[[ -r "$AK_CERT_DER" ]] || { echo "AK_CERT_DER not readable: $AK_CERT_DER" >&2; exit 2; }
[[ -r "$EK_CERT_DER" ]] || { echo "EK_CERT_DER not readable: $EK_CERT_DER" >&2; exit 2; }
[[ -r "$TPM_CREDENTIAL_ACTIVATION_JSON" ]] || { echo "TPM_CREDENTIAL_ACTIVATION_JSON not readable: $TPM_CREDENTIAL_ACTIVATION_JSON" >&2; exit 2; }
IFS=':' read -r -a EK_CHAIN_FILES <<< "$EK_CA_CHAIN_DER"
for cert in "${EK_CHAIN_FILES[@]}"; do
  [[ -n "$cert" && -r "$cert" ]] || { echo "EK_CA_CHAIN_DER entry not readable: $cert" >&2; exit 2; }
done

for cmd in tpm2_quote tpm2_pcrread python3; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd (install tpm2-tools/openssl)" >&2; exit 1; }
done

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

ak_ctx="$TPM_AK_CTX"
ak_name="$TPM_AK_NAME_FILE"
ak_cert="$AK_CERT_DER"
quote_msg="$WORKDIR/quote.msg"
quote_sig="$WORKDIR/quote.sig"
pcr_out="$WORKDIR/pcr.bin"
pcrread="$WORKDIR/pcrread.txt"
ima_log="$WORKDIR/ima.log"

# Quote PCR 0-10 (sha256), binding the channel binding into extraData.
PCR_LIST="sha256:0,1,2,3,4,5,6,7,8,9,10"
tpm2_quote -c "$ak_ctx" -l "$PCR_LIST" -q "$BINDING" \
  -m "$quote_msg" -s "$quote_sig" -o "$pcr_out" -g sha256 >/dev/null 2>&1
tpm2_pcrread "$PCR_LIST" > "$pcrread" 2>/dev/null

# The AK certificate is only the SPKI container used for quote verification.
# Hardware provenance comes from EK-rooted credential activation, and the
# activation token binds this exact AK certificate hash plus the AK name.

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
AK_CERT="$ak_cert" AK_NAME="$ak_name" EK_CERT="$EK_CERT_DER" EK_CA_CHAIN="$EK_CA_CHAIN_DER" \
ACTIVATION_JSON="$TPM_CREDENTIAL_ACTIVATION_JSON" QUOTE_MSG="$quote_msg" QUOTE_SIG="$quote_sig" \
PCRREAD="$pcrread" IMA_LOG="$ima_log" \
python3 - <<'PY'
import json, os, pathlib, re

def hexfile(p):
    return pathlib.Path(p).read_bytes().hex()

def read_chain(spec):
    return [hexfile(p) for p in spec.split(":") if p]

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
    "ek_cert": hexfile(os.environ["EK_CERT"]),
    "ek_ca_chain": read_chain(os.environ["EK_CA_CHAIN"]),
    "ak_name": hexfile(os.environ["AK_NAME"]),
    "credential_activation": json.loads(pathlib.Path(os.environ["ACTIVATION_JSON"]).read_text()),
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
