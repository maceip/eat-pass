# Linux SDK — TEE vs workload surfaces

One mint protocol, two evidence collectors. Do **not** mix gates: the attester
policy and collect path must match the surface you choose.

## When to use which

| | **TEE surface** | **Workload surface** |
|---|-----------------|----------------------|
| **Client class** | `EatPassLinuxTeeClient` | `EatPassLinuxWorkloadClient` |
| **Runs on** | Inside CVM (Azure SEV-SNP, TDX, …) | Linux host without confidential VM |
| **Evidence** | `unified-quote` collect (CBOR EAT / Azure bundle) | TPM2 AK quote JSON + `build_digest` |
| **Attester gate** | `azure` or `uq` | `desktop-tpm` |
| **Policy field** | `allow[].measurement` (launch digest) | `allow[].measurement` = `desktop_build_id_hash(sha256(agent))` |
| **Collect** | `collect_cmd` + `--value-x <binding>` | `scripts/collect-desktop-tpm.sh` |

Both surfaces call the same HTTP flow:

1. `EatPassClient.begin(1)` → `binding`
2. Collect evidence bound to `binding`
3. `POST /authorize` → FAEST-signed authorization
4. `POST /sign` → PoMFRIT blind signatures
5. `finalize` → `Authorization: PrivateToken …`

## TEE example

```python
from eatpass_desktop import EatPassLinuxTeeClient, EatPassLinuxTeeConfig

tee = EatPassLinuxTeeClient(EatPassLinuxTeeConfig(
    attester_url="https://attester.example",
    issuer_url="https://issuer.example",
    collect_cmd="/opt/unified-quote/uq azure collect",
    kt_log_pub_hex="<pinned-kt-log-pub>",
))
header = tee.mint_authorization_header().authorization_header
```

Pre-collected bundle (offline collect):

```python
header = tee.mint_from_bundle_file("/tmp/azure-bundle.json").authorization_header
```

## Workload example

```python
from eatpass_desktop import EatPassLinuxWorkloadClient, EatPassLinuxWorkloadConfig

agent = EatPassLinuxWorkloadClient(EatPassLinuxWorkloadConfig(
    attester_url="https://attester.example",
    issuer_url="https://issuer.example",
    build_digest_hex="abc…",  # sha256(agent binary), 64 hex chars
))
header = agent.mint_authorization_header().authorization_header
```

Requires `tpm2-tools` on PATH for default collect script.

## Operator checklist

**TEE path**

```bash
eat-pass attester --gate azure --policy policy/examples/uqaz1-example.json
# allow[].measurement = CVM launch digest
```

**Workload path**

```bash
eat-pass desktop-hash-build ./target/release/my-agent
# put build_id_hash in policy allow[].measurement
eat-pass attester --gate desktop-tpm --policy policy/examples/desktop-linux-tpm-example.json
```

## Windows note

Windows agents use the same **workload** model (TPM, no TEE) via
`EatPassDesktopClient` or `desktop/sdk-windows` — not the Linux package split.
