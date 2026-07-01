# eat-pass SDKs (all platforms)

Coupled mint: **attest → policy (FAEST) → blind mint (PoMFRIT) → spend**.

| Platform | SDK | Surface | Attester gate |
|----------|-----|---------|---------------|
| **Linux (CVM)** | `eatpass_desktop.linux.tee` | TEE / confidential VM | `azure`, `uq` |
| **Linux (agent)** | `eatpass_desktop.linux.workload` | Host TPM2 EK + activation, no TEE | `desktop-tpm` |
| **Windows** | `eatpass_desktop` / `sdk-windows` | Host TPM2 EK + activation | `desktop-tpm` |
| **macOS** | `desktop/sdk-macos` | App Attest | `macos-app-attest` |
| **iOS** | `mobile/sdk-ios` | App Attest | `ios-app-attest` |
| **Android** | `mobile/sdk-android` | Key Attestation | `android-key` |

Shared crypto: **`eat-pass-mobile`** (`EatPassClient.begin` / `finalize`).

## Linux — two surfaces (same mint protocol)

Linux is the only platform with **two first-class SDK entry points**. Pick by **where the code runs**, not by language:

```
┌─────────────────────────────────────────────────────────────┐
│  EatPassLinuxTeeClient          EatPassLinuxWorkloadClient  │
│  (inside SEV-SNP / TDX CVM)     (bare metal, VM, k8s, laptop)│
│  uq/azure collect               TPM2 + sha256(agent binary) │
│  policy: launch measurement     policy: desktop_build_id_hash│
└─────────────────────────────────────────────────────────────┘
                              │
                    same: begin(binding) → /authorize → /sign → finalize
```

### TEE surface (CVM agent)

```python
from eatpass_desktop import EatPassLinuxTeeClient, EatPassLinuxTeeConfig

client = EatPassLinuxTeeClient(EatPassLinuxTeeConfig(
    attester_url="http://127.0.0.1:8087",
    issuer_url="http://127.0.0.1:8088",
    collect_cmd="uq azure collect",  # runs with --value-x <binding> -o <tmp>
))
print(client.mint_authorization_header().authorization_header)
```

Attester: `eat-pass attester --gate azure --policy policy/examples/uqaz1-example.json`

### Workload surface (no TEE)

```python
from eatpass_desktop import EatPassLinuxWorkloadClient, EatPassLinuxWorkloadConfig

client = EatPassLinuxWorkloadClient(EatPassLinuxWorkloadConfig(
    attester_url="http://127.0.0.1:8087",
    issuer_url="http://127.0.0.1:8088",
    build_digest_hex="<sha256-hex-of-agent-binary>",
))
print(client.mint_authorization_header().authorization_header)
```

Attester: `eat-pass attester --gate desktop-tpm --policy policy/examples/desktop-linux-tpm-example.json`

Policy digest: `eat-pass desktop-hash-build ./your-agent`
TPM policies also need `desktop_tpm_ek_roots` and
`desktop_tpm_activation_pubkeys`; see `docs/platform-support-matrix.md`.

See [../docs/linux-sdk.md](../docs/linux-sdk.md).

## Build native crypto

```bash
cd eat-pass
cargo build -p eat-pass-mobile
./desktop/generate-bindings.sh   # Python + Kotlin + Swift
pip install -e desktop/sdk-python
```

## Other platforms

- **Windows:** `desktop/sdk-windows` (C# + `eat-pass-mobile-ffi`)
- **macOS / iOS:** Swift packages under `desktop/sdk-macos`, `mobile/sdk-ios`
- **Android:** `mobile/sdk-android`

Wire protocol: [docs/desktop-coupled-protocol.md](docs/desktop-coupled-protocol.md)
