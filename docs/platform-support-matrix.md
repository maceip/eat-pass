# Platform support matrix

This is the current implementation status, not a product claim. The important
distinction is whether a platform has only a verifier library, a policy-backed
eat-pass gate, a collector/SDK, and an operator provisioning story.

`desktop_tpm_ek_roots` means SHA-256 pins for DER TPM Endorsement Key root
certificates: TPM manufacturer roots or privacy-CA roots. It applies to Linux
and Windows TPM2 hosts under the `desktop-tpm` gate. It is not a macOS, iOS, or
Android concept.

| Platform / surface | Gate / profile | Collector / SDK | What is enforced now | Policy anchors | Status | Remaining gap |
|---|---|---|---|---|---|---|
| Azure Linux CVM, SEV-SNP vTPM | `azure` / `azure-snp-bundle`; `azure-tls` / `azure-attested-tls` | `uq azure collect`; attested-TLS cert path | AMD-rooted SNP report through Azure vTPM, channel binding, and value-x binding | `allow[].measurement` | Policy-backed gate implemented | Keep live Azure fixture coverage current; document production key rotation |
| Generic unified-quote EAT, SEV-SNP | `uq` / `uq-eat` | unified-quote collector | EAT nonce binding and AMD quote verification | `allow[].measurement` | Policy-backed gate implemented | Production examples still lean on Azure-specific bundle path |
| Generic unified-quote EAT, Intel TDX | `uq` / `uq-eat` | unified-quote collector | EAT nonce binding and TDX quote verification, when collector supplies TDX evidence | `allow[].measurement` | Verifier compiled into gate | Need live TDX policy example and smoke fixture |
| AWS Nitro Enclave | intended `uq` / `uq-eat` | unified-quote Nitro support | unified-quote can verify Nitro roots, but eat-pass gate does not enable the `nitro` feature | `allow[].measurement` / Nitro PCR identity | Gap | Enable Nitro in `eat-pass-gate`, add policy example, test fixture, and collector docs |
| Linux host / desktop TPM2 | `desktop-tpm` / `desktop-tpm-client` | `scripts/collect-desktop-tpm.sh`; Python workload SDK | AK quote binding, EK chain to pinned root, credential-activation token, optional PCR/IMA checks | `allow[].measurement`, `desktop_tpm_ek_roots`, `desktop_tpm_activation_pubkeys`, optional `boot_aggregates`, `require_ima` | Policy-backed gate implemented | Activation service/provisioning flow is still operator-supplied; IMA proof requires host kernel setup |
| Windows host / desktop TPM2 | `desktop-tpm` / `desktop-tpm-client` | `scripts/collect-desktop-tpm-windows.ps1`; C# SDK wrapper | Same verifier as Linux; collector now requires AK/EK/activation inputs and emits EK chain + activation token | Same as Linux TPM | Gate implemented; collector fail-closed | Needs real Windows TPM smoke test and provisioning guide; no IMA path |
| macOS desktop App Attest | `macos-app-attest` / `macos-app-attest` | Swift desktop SDK | Assertion signature over eat-pass binding and app id hash | `allow[].app_id_hash` | Policy-backed gate partial | Missing server-side App Attest enrollment/root validation and key lifecycle |
| iOS App Attest | `ios-app-attest` / `ios-app-attest` | Swift mobile SDK | Assertion signature over eat-pass binding and app id hash | `allow[].app_id_hash` | Policy-backed gate partial | Missing server-side App Attest enrollment/root validation and key lifecycle |
| Android KeyMint | `android-key` / `android-key-attestation` | Kotlin SDK | Chain link signatures and binding/package/cert bytes in attestation extension | `allow[].app_id_hash` | Policy-backed gate partial | Needs Android root pins and real ASN.1 KeyMint extension parsing for challenge, package, signer, security level, rollback state |
| macOS host-attested guest | no eat-pass gate yet | Swift `HostAttestedGuest`; unified-quote relay types | Library data model only | none yet | Gap | Add eat-pass evidence profile/gate, relay verifier, policy fields, and replay-resistant service path |
| Relay / bootstrap freshness | no eat-pass service yet | unified-quote `relay.rs` library | Typed challenges and in-memory replay stores in library | none yet | Library only | Durable replay store, service API, and tests across restart are missing |

## Closed in this pass

- The desktop TPM policy fields are no longer just schema: `DesktopTpmVerifier`
  carries EK-root pins and activation signer keys into the hardened
  unified-quote verifier.
- The attester and standalone `verify-desktop-tpm` command now use policy-backed
  desktop TPM verification.
- The Linux and Windows TPM collectors no longer intentionally emit
  self-signed-AK-only trust evidence.
- All eat-pass crates that depend on unified-quote now pin the same hardened
  unified-quote revision.
