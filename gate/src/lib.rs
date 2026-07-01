//! `eat-pass-gate` — the real attestation gate (milestone m2).
//!
//! [`UqVerifier`] implements [`eat_pass_core::gate::AttestationVerifier`] against
//! a live [`unified-quote`](https://github.com/maceip/unified-quote) EAT, so an
//! issuer mints tokens only for a request that carries a genuine hardware
//! attestation from an accepted build. This replaces `DevVerifier` (the ed25519
//! stand-in) on the production path.
//!
//! ## How the channel binding reaches the hardware
//!
//! eat-pass's per-request **channel binding** is `binding_of(blinded)` — a hash
//! over the blinded token inputs the client sends. For the attestation to be
//! non-replayable against a *different* blind request, the hardware quote must
//! commit to that exact value. unified-quote already has the slot for it: the
//! verifier-supplied freshness nonce (`eat_nonce`, the L1.1 design). The flow is:
//!
//! 1. the client computes `binding = binding_of(blinded)` (in `Client::begin`),
//! 2. it asks its local TEE for a quote with `UQ_EAT_NONCE = binding` — so the
//!    EAT's `eat_nonce` *is* the channel binding,
//! 3. `EatToken::binding_bytes()` folds `eat_nonce` in, and that value lands in
//!    the quote's `report_data[0..32]`, which the hardware signs.
//!
//! [`UqVerifier::verify`] therefore:
//! - decodes the EAT,
//! - requires `eat.eat_nonce == expected_binding` (the channel-binding tie),
//! - calls [`unified_quote::quote::verify::verify_platform_quote`] with
//!   `eat.binding_bytes()`, which checks the vendor cert chain (AMD/Intel root)
//!   **and** that `report_data[0..32] == binding_bytes()`,
//! - returns the EAT's `value_x` (the build identity) as the
//!   [`Measurement`](eat_pass_core::gate::Measurement) the gate allowlists.
//!
//! Only if every step passes does the issuer blind-sign.

use eat_pass_core::gate::{AttestationVerifier, GateError, Measurement};
use unified_quote::eat::EatToken;
use unified_quote::quote::verify::verify_platform_quote;
use unified_quote::quote::Platform;
use unified_quote::tee::azure::{self, AzureBundle};
use unified_quote::tee::mobile::android::{self, AndroidKeyAttestationBundle};
use unified_quote::tee::mobile::ios::{self, IosAppAttestBundle};

/// Verifies a unified-quote EAT and extracts the build measurement, enforcing
/// that the attestation commits to eat-pass's channel binding via `eat_nonce`.
#[derive(Clone, Copy, Default)]
pub struct UqVerifier;

impl UqVerifier {
    pub fn new() -> Self {
        Self
    }
}

/// The platform string recorded in the extracted [`Measurement`].
fn platform_label(p: Platform) -> &'static str {
    match p {
        Platform::Nitro => "nitro",
        Platform::SevSnp => "sev-snp",
        Platform::Tdx => "tdx",
    }
}

impl AttestationVerifier for UqVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        // 1. Decode + shape-validate the EAT (version + profile).
        let token = EatToken::from_cbor(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("eat decode: {e}")))?;

        // 2. Channel-binding tie: the eat-pass channel binding must be the
        //    hardware freshness nonce. Without this an EAT for one blind request
        //    could be replayed against another.
        if &token.eat_nonce != expected_binding {
            return Err(GateError::BindingMismatch);
        }

        // 3. Resolve the platform discriminant.
        let platform = token.platform_enum().ok_or_else(|| {
            GateError::AttestationInvalid(format!("unknown platform {}", token.platform))
        })?;

        // 4. Verify the hardware quote against the pinned vendor root AND that
        //    report_data[0..32] == binding_bytes() (which folds in eat_nonce).
        let expected = token.binding_bytes();
        verify_platform_quote(platform, &token.platform_quote, &expected)
            .map_err(|e| GateError::AttestationInvalid(format!("platform quote: {e}")))?;

        // 5. The gated identity is the build's Value X.
        Ok(Measurement::new(
            platform_label(platform),
            token.value_x.to_vec(),
        ))
    }
}

/// Verifies an **Azure SEV-SNP vTPM** attestation bundle (the format the live
/// `attest.secure.build` CVM emits) and extracts the SNP launch measurement.
///
/// On Azure CVMs the paravisor owns the SNP `report_data` (it commits it to the
/// vTPM AK), so eat-pass cannot place its channel binding directly in the SNP
/// report. Instead the in-CVM client collects a bundle with
/// `value_x = binding_of(blinded)` — the AK-signed TPM2 quote then commits that
/// 32-byte value as its `qualifyingData`. [`unified_quote::tee::azure::verify_bundle`]
/// proves (a) the SNP report chains to the AMD root, (b) `report_data ==
/// sha256(runtime)` so the vTPM AK is hardware-endorsed, and (c) the AK quote
/// binds `value_x`. This verifier additionally requires `value_x ==
/// expected_binding` (the channel-binding tie) and returns the **SNP launch
/// MEASUREMENT** as the allowlisted build identity.
///
/// Wrap in [`eat_pass_core::gate::ClassGated`] to enforce a measurement class.
#[derive(Clone, Copy, Default)]
pub struct AzureUqVerifier;

impl AzureUqVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for AzureUqVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let bundle: AzureBundle = serde_json::from_slice(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("azure bundle parse: {e}")))?;

        // eat-pass's in-CVM client binds value_x = channel binding via the AK
        // quote. An attested-TLS bundle (tls_spki set) binds sha256(spki||value_x)
        // instead and must be verified through the cert path, not here.
        if bundle.tls_spki.is_some() {
            return Err(GateError::AttestationInvalid(
                "azure bundle carries tls_spki (attested-TLS shape); use the cert verifier".into(),
            ));
        }

        let verdict = azure::verify_bundle(&bundle)
            .map_err(|e| GateError::AttestationInvalid(format!("azure verify: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "azure verdict: {}",
                verdict.verdict
            )));
        }

        // Channel-binding tie: the AK-quoted value_x must equal expected_binding.
        let bound_hex = verdict.value_x.ok_or_else(|| {
            GateError::AttestationInvalid("azure bundle not value_x-bound (no AK quote)".into())
        })?;
        let bound = hex::decode(&bound_hex)
            .map_err(|e| GateError::AttestationInvalid(format!("value_x hex: {e}")))?;
        if bound.as_slice() != expected_binding {
            return Err(GateError::BindingMismatch);
        }

        // The gated build identity is the SNP launch MEASUREMENT.
        let measurement = hex::decode(&verdict.measurement)
            .map_err(|e| GateError::AttestationInvalid(format!("measurement hex: {e}")))?;
        Ok(Measurement::new("azure-sev-snp-vtpm", measurement))
    }
}

/// Verifies an Android KeyMint attestation bundle (no Play Integrity).
#[derive(Clone, Copy, Default)]
pub struct AndroidKeyAttestationVerifier;

impl AndroidKeyAttestationVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for AndroidKeyAttestationVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let bundle: AndroidKeyAttestationBundle = serde_json::from_slice(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("android bundle: {e}")))?;
        let verdict = android::verify_bundle(&bundle, expected_binding)
            .map_err(|e| GateError::AttestationInvalid(format!("android verify: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "android verdict: {}",
                verdict.verdict
            )));
        }
        let app_id = hex::decode(&verdict.app_id_hash)
            .map_err(|e| GateError::AttestationInvalid(format!("app_id_hash: {e}")))?;
        Ok(Measurement::new(
            unified_quote::tee::mobile::ANDROID_PLATFORM,
            app_id,
        ))
    }
}

/// Verifies an iOS App Attest assertion bound to eat-pass channel binding.
#[derive(Clone, Copy, Default)]
pub struct IosAppAttestVerifier;

impl IosAppAttestVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for IosAppAttestVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let bundle: IosAppAttestBundle = serde_json::from_slice(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("ios bundle: {e}")))?;
        let verdict = ios::verify_bundle(&bundle, expected_binding)
            .map_err(|e| GateError::AttestationInvalid(format!("ios verify: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "ios verdict: {}",
                verdict.verdict
            )));
        }
        let app_id = hex::decode(&verdict.app_id_hash)
            .map_err(|e| GateError::AttestationInvalid(format!("app_id_hash: {e}")))?;
        Ok(Measurement::new(
            unified_quote::tee::mobile::IOS_PLATFORM,
            app_id,
        ))
    }
}

/// Verifies an **Azure attested-TLS leaf certificate** — the exact evidence the
/// live `attest.secure.build` CVM presents in its TLS handshake.
///
/// The `eat` argument is the DER of the TLS leaf cert; its TCG-DICE extension
/// carries an [`AzureBundle`] whose AK quote binds `sha256(cert_spki || value_x)`.
/// [`unified_quote::tee::azure::verify_attested_cert`] checks the cert SPKI
/// matches the bundle (channel binding, anti-relay), the SNP report chains to
/// the AMD root, and the AK quote binds the TLS key + `value_x`. This verifier
/// additionally requires `value_x == expected_binding` and returns the SNP
/// launch MEASUREMENT as the gated build identity.
#[derive(Clone, Copy, Default)]
pub struct AzureTlsVerifier;

impl AzureTlsVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for AzureTlsVerifier {
    /// `eat` is the DER bytes of the attested-TLS leaf certificate.
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let verdict = azure::verify_attested_cert(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("azure attested-tls: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "azure verdict: {}",
                verdict.verdict
            )));
        }
        let bound_hex = verdict.value_x.ok_or_else(|| {
            GateError::AttestationInvalid("attested-tls bundle not value_x-bound".into())
        })?;
        let bound = hex::decode(&bound_hex)
            .map_err(|e| GateError::AttestationInvalid(format!("value_x hex: {e}")))?;
        if bound.as_slice() != expected_binding {
            return Err(GateError::BindingMismatch);
        }
        let measurement = hex::decode(&verdict.measurement)
            .map_err(|e| GateError::AttestationInvalid(format!("measurement hex: {e}")))?;
        Ok(Measurement::new("azure-sev-snp-vtpm", measurement))
    }
}

/// Verifies a Linux or Windows TPM2 client bundle (desktop agent, no CVM).
///
/// With no policy it authenticates the AK quote + channel binding only (the
/// agent binary identity is the self-reported `build_digest`). Configured via
/// [`DesktopTpmVerifier::with_policy`], it additionally requires a
/// hardware-measured IMA log and/or a known-good boot-aggregate.
#[derive(Clone, Default)]
pub struct DesktopTpmVerifier {
    require_ima: bool,
    boot_aggregates: Vec<[u8; 32]>,
}

impl DesktopTpmVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure the IMA / boot-aggregate posture from operator policy.
    /// `require_ima` rejects channel-bound-only bundles; a non-empty
    /// `boot_aggregates` allowlist requires the quoted boot state (PCR 0-9) to
    /// match a known-good fingerprint.
    pub fn with_policy(require_ima: bool, boot_aggregates: Vec<[u8; 32]>) -> Self {
        Self {
            require_ima,
            boot_aggregates,
        }
    }
}

impl AttestationVerifier for DesktopTpmVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let bundle: unified_quote::tee::desktop::tpm::TpmClientBundle = serde_json::from_slice(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("desktop tpm bundle: {e}")))?;
        let verdict = unified_quote::tee::desktop::tpm::verify_bundle(&bundle, expected_binding)
            .map_err(|e| GateError::AttestationInvalid(format!("desktop tpm: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "desktop tpm verdict: {}",
                verdict.verdict
            )));
        }
        if self.require_ima && !verdict.ima_verified {
            return Err(GateError::AttestationInvalid(
                "policy requires IMA-measured attestation but bundle is channel-bound only".into(),
            ));
        }
        if !self.boot_aggregates.is_empty() {
            let matches = verdict
                .boot_aggregate
                .as_deref()
                .and_then(|h| hex::decode(h).ok())
                .map(|b| {
                    self.boot_aggregates
                        .iter()
                        .any(|a| a.as_slice() == b.as_slice())
                })
                .unwrap_or(false);
            if !matches {
                return Err(GateError::MeasurementNotAllowed);
            }
        }
        let value_x = hex::decode(&verdict.identity_hash)
            .map_err(|e| GateError::AttestationInvalid(format!("identity_hash: {e}")))?;
        Ok(Measurement::new(verdict.platform, value_x))
    }
}

/// Verifies a macOS App Attest bundle for desktop agents.
#[derive(Clone, Copy, Default)]
pub struct MacOsAppAttestVerifier;

impl MacOsAppAttestVerifier {
    pub fn new() -> Self {
        Self
    }
}

impl AttestationVerifier for MacOsAppAttestVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let bundle: unified_quote::tee::desktop::app_attest::MacOsAppAttestBundle =
            serde_json::from_slice(eat)
                .map_err(|e| GateError::AttestationInvalid(format!("macos bundle: {e}")))?;
        let verdict =
            unified_quote::tee::desktop::app_attest::verify_bundle(&bundle, expected_binding)
                .map_err(|e| GateError::AttestationInvalid(format!("macos app attest: {e}")))?;
        if verdict.verdict != "verified" {
            return Err(GateError::AttestationInvalid(format!(
                "macos verdict: {}",
                verdict.verdict
            )));
        }
        let value_x = hex::decode(&verdict.identity_hash)
            .map_err(|e| GateError::AttestationInvalid(format!("app_id_hash: {e}")))?;
        Ok(Measurement::new(verdict.platform, value_x))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically valid EAT whose nonce we control, but whose platform_quote
    // is junk — exercises the binding/platform branches without needing real
    // hardware or network (the full crypto path runs against the live node).
    fn eat_with_nonce(nonce: [u8; 32], platform: u8, quote: Vec<u8>) -> Vec<u8> {
        let token = EatToken {
            version: unified_quote::eat::EAT_VERSION,
            eat_profile: unified_quote::eat::EAT_PROFILE.to_string(),
            binding_suite: unified_quote::eat::DEFAULT_BINDING_SUITE,
            value_x: [0xAB; 48],
            platform,
            platform_measurement: vec![0u8; 48],
            platform_quote: quote,
            tls_spki_hash: [0u8; 32],
            source_hash: [0u8; 48],
            artifact_hash: [0u8; 48],
            iat: 1,
            eat_nonce: nonce,
            previous_attestation: Vec::new(),
        };
        token.to_cbor().expect("encode")
    }

    #[test]
    fn rejects_nonce_not_equal_to_binding() {
        let v = UqVerifier::new();
        let eat = eat_with_nonce([1u8; 32], 2 /* sev-snp */, vec![0u8; 8]);
        let binding = [2u8; 32]; // different from the eat_nonce
        assert_eq!(v.verify(&eat, &binding), Err(GateError::BindingMismatch));
    }

    #[test]
    fn rejects_unknown_platform() {
        let v = UqVerifier::new();
        let nonce = [7u8; 32];
        let eat = eat_with_nonce(nonce, 9 /* not a platform */, vec![0u8; 8]);
        match v.verify(&eat, &nonce) {
            Err(GateError::AttestationInvalid(msg)) => assert!(msg.contains("unknown platform")),
            other => panic!("expected AttestationInvalid, got {other:?}"),
        }
    }

    #[test]
    fn passes_binding_then_fails_on_bogus_quote() {
        // nonce matches the binding (step 2 passes), platform is known (step 3),
        // but the quote is garbage so platform verification (step 4) must reject.
        let v = UqVerifier::new();
        let nonce = [9u8; 32];
        let eat = eat_with_nonce(nonce, 2 /* sev-snp */, vec![0xFF; 64]);
        match v.verify(&eat, &nonce) {
            Err(GateError::AttestationInvalid(msg)) => assert!(msg.contains("platform quote")),
            other => panic!("expected AttestationInvalid(platform quote …), got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_cbor() {
        let v = UqVerifier::new();
        let err = v.verify(&[0xDE, 0xAD, 0xBE, 0xEF], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, GateError::AttestationInvalid(_)));
    }

    #[test]
    fn azure_rejects_malformed_bundle() {
        let v = AzureUqVerifier::new();
        let err = v.verify(b"not json", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, GateError::AttestationInvalid(_)));
    }

    #[test]
    fn azure_rejects_attested_tls_shape() {
        // A bundle carrying tls_spki binds sha256(spki||value_x), not value_x;
        // it must go through the cert verifier, so this path rejects it early.
        let v = AzureUqVerifier::new();
        let bundle = serde_json::json!({
            "version": 1,
            "platform": "azure-sev-snp-vtpm",
            "hcl": "00",
            "tls_spki": "aa"
        })
        .to_string();
        match v.verify(bundle.as_bytes(), &[0u8; 32]) {
            Err(GateError::AttestationInvalid(m)) => assert!(m.contains("tls_spki")),
            other => panic!("expected AttestationInvalid(tls_spki …), got {other:?}"),
        }
    }

    #[test]
    fn desktop_tpm_rejects_malformed_bundle() {
        let v = DesktopTpmVerifier::new();
        let err = v.verify(b"not json", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, GateError::AttestationInvalid(_)));
    }

    #[test]
    fn macos_rejects_malformed_bundle() {
        let v = MacOsAppAttestVerifier::new();
        let err = v.verify(b"not json", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, GateError::AttestationInvalid(_)));
    }
}
