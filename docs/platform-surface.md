# Platform surface — policy is the interface

Every platform uses the **same operator contract**: a `VerificationPolicy` JSON file.
The attester **`--gate`** picks the evidence wire format; **`allow`** picks who may mint.

There are no separate “gauges” — only **gates** (crypto verifier backend) and **policy**
(appraisal after verify).

## Surfaces (pick by where the agent runs)

| Surface | Agent | Attester `--gate` | `evidence_profile` | Policy field | SDK | Trust |
|---------|-------|-------------------|----------------------|--------------|-----|-------|
| **Confidential cloud** | CVM agent | `azure` or `uq` | `azure-snp-bundle` / `uq-eat` | `measurement` (launch digest) | `EatPassLinuxTeeClient` | AMD / Intel silicon |
| **Linux workload** | Host / k8s agent | `desktop-tpm` | `desktop-tpm-client` | `measurement` (build id hash) | `EatPassLinuxWorkloadClient` | Host TPM2 |
| **Windows desktop** | Enterprise agent | `desktop-tpm` | `desktop-tpm-client` | `measurement` | `EatPass.Desktop` (C#) | TPM2 |
| **macOS desktop** | Signed app agent | `macos-app-attest` | `macos-app-attest` | `app_id_hash` | `EatPassDesktop` (Swift) | Apple App Attest |
| **iOS mobile** | App agent | `ios-app-attest` | `ios-app-attest` | `app_id_hash` | `EatPassMobile` (Swift) | Apple App Attest |
| **Android mobile** | App agent | `android-key` | `android-key-attestation` | `app_id_hash` | `EatPassMobile` (Kotlin) | KeyMint chain |

Same mint protocol everywhere: **`begin(binding) → /authorize → /sign → finalize`**.

## One policy file per gate profile

```bash
# confidential cloud (hero demos)
eat-pass attester --gate azure --policy policy/examples/uqaz1-example.json

# linux host agent (no TEE)
eat-pass attester --gate desktop-tpm --policy policy/examples/desktop-linux-tpm-example.json

# macOS app
eat-pass attester --gate macos-app-attest --policy policy/examples/desktop-macos-app-attest-example.json

# android / ios
eat-pass attester --gate android-key --policy policy/examples/mobile-android-example.json
eat-pass attester --gate ios-app-attest --policy policy/examples/mobile-ios-example.json
```

## What the policy decides (after crypto)

| Check | Meaning |
|-------|---------|
| `ReferenceValueMatch` | `measurement` or `app_id_hash` in `allow` |
| `BindingOk` | Hardware quote commits to this mint's binding |
| `ProfileMatch` | Evidence matches gate (`evidence_profile`) |
| `PolicyNotExpired` | `valid_until` |
| `RegistryStatus` | Optional registry tier |

Human + agent tooling:

```bash
eat-pass policy validate --file policy/examples/uqaz1-example.json
eat-pass policy simulate --policy policy/examples/uqaz1-example.json --claims claims.json
eat-pass policy diff left.json right.json
```

## Privileged tools (cvm-agent)

Policy gates **mint**. **tool-gate** gates **spend on privileged tools** (email first):

```
Agent (in CVM) ──PoMFRIT token──► tool-gate ──SMTP──► mail
                      ▲
              eat-pass attester (azure gate + policy)
```

SMTP credentials never leave the tool-gate host. See [`demos/tool-gate/`](../demos/tool-gate/).

## Example policy paths

| Surface | Example policy |
|---------|----------------|
| Azure CVM | `policy/examples/uqaz1-example.json` |
| Linux TPM | `policy/examples/desktop-linux-tpm-example.json` |
| macOS | `policy/examples/desktop-macos-app-attest-example.json` |
| Android | `policy/examples/mobile-android-example.json` |
| iOS | `policy/examples/mobile-ios-example.json` |

Full spec: [`docs/verification-policy.md`](../docs/verification-policy.md)
