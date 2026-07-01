# Desktop client attestation (Linux / Windows / macOS)

Non-CVM agent workloads use the same eat-pass gate as CVM and mobile:

1. Client computes `binding = binding_of(blinded)`.
2. Host collects evidence JSON bound to `binding`.
3. Attester `--gate` verifies evidence → `Measurement { platform, value_x }`.
4. Policy allowlists `value_x` (build identity).

## Gates

| `--gate` | OS | Evidence | Policy field |
|----------|-----|----------|----------------|
| `desktop-tpm` | Linux, Windows | TPM2 AK quote JSON + EK chain + credential-activation token | `allow[].measurement` = `build_id_hash` |
| `macos-app-attest` | macOS | App Attest assertion JSON | `allow[].app_id_hash` |

Wire formats live in `unified-quote/v2/src/tee/desktop/`.

## Linux / Windows (TPM2)

**Build identity:** `build_id_hash = desktop_build_id_hash(sha256(agent_binary))`

```bash
eat-pass desktop-hash-build ./target/release/eat-pass
# put build_id_hash in policy allow[].measurement
```

**Trust anchors:** desktop TPM policies must pin EK roots and activation-token
signer keys:

```json
"desktop_tpm_ek_roots": ["<sha256 DER EK root cert hex>"],
"desktop_tpm_activation_pubkeys": ["<Ed25519 activation signer pubkey hex>"]
```

The verifier rejects bundles without an EK certificate chain ending at a pinned
root and a fresh makecredential/activatecredential success token for the AK
name, EK certificate, AK certificate, and eat-pass binding. A self-signed AK
certificate alone is only enough to parse the AK public key; it is not accepted
as TPM hardware provenance.

An EK root is a TPM manufacturer or privacy-CA root, not an operating-system
root. The same policy fields are used for Linux and Windows TPM2 hosts.

**Collect bundle (Linux, requires tpm2-tools and provisioning material):**

```bash
BINDING=<64-hex> BUILD_DIGEST=<64-hex> \
  TPM_AK_CTX=ak.ctx \
  TPM_AK_NAME_FILE=ak.name \
  AK_CERT_DER=ak.der \
  EK_CERT_DER=ek.der \
  EK_CA_CHAIN_DER="ek-intermediate.der:ek-root.der" \
  TPM_CREDENTIAL_ACTIVATION_JSON=activation.json \
  ./scripts/collect-desktop-tpm.sh -o bundle.json
```

**Attester:**

```bash
eat-pass attester --gate desktop-tpm --policy policy/examples/desktop-linux-tpm-example.json
```

**Client mint:**

```bash
eat-pass token --attest-mode desktop-tpm \
  --build-digest <sha256-hex-of-agent-binary> \
  --desktop-collect scripts/collect-desktop-tpm.sh \
  ...
```

Or pass evidence bytes through the primary evidence input:

```bash
eat-pass token --evidence bundle.json ...
```

## SDKs

Platform orchestrators live under `desktop/` and `mobile/sdk-ios/`:

| OS | Package |
|----|---------|
| Linux / Windows | `desktop/sdk-python` (`EatPassDesktopClient`) |
| Windows | `desktop/sdk-windows` (`EatPass.Desktop`) |
| macOS | `desktop/sdk-macos` (`EatPassDesktopClient`) |
| iOS | `mobile/sdk-ios` (`EatPassMobileClient`) |
| Android | `mobile/sdk-android` (`EatPassMobileClient`) |

Build native crypto: `cargo build -p eat-pass-mobile && ./desktop/generate-bindings.sh`

See [../desktop/README.md](../desktop/README.md).

**Verify:**

The standalone verifier path uses the same policy trust anchors as the
attester:

```bash
eat-pass verify-desktop-tpm \
  --bundle bundle.json \
  --binding <hex> \
  --policy policy/examples/desktop-linux-tpm-example.json
```

Windows hosts produce the same JSON with `"platform": "windows-tpm-client"`.
Use semicolon-separated paths for `EK_CA_CHAIN_DER`, for example
`ek-intermediate.der;ek-root.der`, because Windows drive-letter paths contain
colons. PowerShell/tpm2-tss collection is host-specific; verifier is shared.

## macOS (App Attest)

Same crypto as iOS; platform label `macos-app-attest`. Host app must call `DCAppAttestService` `generateAssertion` with `client_data_hash = ios_client_data_hash(binding)`.

Policy uses `app_id_hash` (team + bundle id), same as iOS.

```bash
eat-pass attester --gate macos-app-attest --policy policy/examples/desktop-macos-app-attest-example.json
eat-pass verify-macos-app-attest --bundle macos.json --binding <hex>
```

## Cloud agent sandboxes

Platform-operated workers can use `desktop-tpm` with a pinned worker binary digest, or stay on CVM gates (`azure`, `uq`) when confidential VMs are available.
