//! The attestation gate: issuance is allowed only for a request that carries a
//! valid attestation (an "eat") which commits to the request's channel binding
//! and whose measurement the issuer accepts.
//!
//! [`AttestationVerifier`] is the seam. This module ships [`DevVerifier`] (an
//! ed25519-signed dev statement) so the protocol is testable on every platform
//! with no TEE hardware. The real `unified-quote` EAT verifier lives in the
//! `eat-pass-gate` crate (milestone m2).

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const DEV_EAT_DOMAIN: &[u8] = b"eat-pass/v0/dev-eat\0";

/// What an attestation proves: a platform + a measurement (the build identity,
/// e.g. a `unified-quote` `value_x`). Never an identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    pub platform: String,
    #[serde(with = "crate::serdehelp::b64vec")]
    pub value_x: Vec<u8>,
}

impl Measurement {
    pub fn new(platform: impl Into<String>, value_x: Vec<u8>) -> Self {
        Self {
            platform: platform.into(),
            value_x,
        }
    }
}

/// Gate verdicts. Mirrors the failure taxonomy of google's `ArateaAuthError`,
/// recast for attestation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateError {
    #[error("attestation invalid: {0}")]
    AttestationInvalid(String),
    #[error("measurement not allowed")]
    MeasurementNotAllowed,
    #[error("channel binding mismatch")]
    BindingMismatch,
    #[error("quota exceeded")]
    QuotaExceeded,
    #[error("unknown: {0}")]
    Unknown(String),
}

/// Verifies an attestation blob and extracts the measurement it proves, while
/// enforcing that it commits to `expected_binding`.
pub trait AttestationVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError>;
}

fn dev_signed_bytes(m: &Measurement, binding: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(DEV_EAT_DOMAIN.len() + m.platform.len() + m.value_x.len() + 34);
    v.extend_from_slice(DEV_EAT_DOMAIN);
    v.extend_from_slice(m.platform.as_bytes());
    v.push(0);
    v.extend_from_slice(&m.value_x);
    v.push(0);
    v.extend_from_slice(binding);
    v
}

/// Wire form of a dev attestation.
#[derive(Clone, Serialize, Deserialize)]
struct DevEat {
    platform: String,
    #[serde(with = "crate::serdehelp::b64vec")]
    value_x: Vec<u8>,
    #[serde(with = "crate::serdehelp::hex32")]
    binding: [u8; 32],
    #[serde(with = "crate::serdehelp::b64vec")]
    sig: Vec<u8>,
}

/// A stand-in attester for tests/local: signs `(measurement, binding)` with an
/// ed25519 key. The real attester is a TEE producing a `unified-quote` EAT.
pub struct DevAttester {
    sk: SigningKey,
}

impl DevAttester {
    pub fn generate() -> Result<Self, GateError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| GateError::Unknown(e.to_string()))?;
        Ok(Self {
            sk: SigningKey::from_bytes(&seed),
        })
    }

    /// The public key a [`DevVerifier`] is configured to trust.
    pub fn verifying_key(&self) -> [u8; 32] {
        self.sk.verifying_key().to_bytes()
    }

    /// Produce a dev eat binding `measurement` to `binding`.
    pub fn attest(&self, measurement: &Measurement, binding: &[u8; 32]) -> Vec<u8> {
        let sig = self.sk.sign(&dev_signed_bytes(measurement, binding));
        let eat = DevEat {
            platform: measurement.platform.clone(),
            value_x: measurement.value_x.clone(),
            binding: *binding,
            sig: sig.to_bytes().to_vec(),
        };
        serde_json::to_vec(&eat).expect("DevEat is serializable")
    }
}

/// Verifies dev eats against a trusted attester key and a measurement allowlist.
pub struct DevVerifier {
    vk: VerifyingKey,
    allow: HashSet<Vec<u8>>,
}

impl DevVerifier {
    pub fn new(
        attester_key: [u8; 32],
        allow: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, GateError> {
        let vk = VerifyingKey::from_bytes(&attester_key)
            .map_err(|e| GateError::AttestationInvalid(e.to_string()))?;
        Ok(Self {
            vk,
            allow: allow.into_iter().collect(),
        })
    }
}

impl AttestationVerifier for DevVerifier {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let eat: DevEat = serde_json::from_slice(eat)
            .map_err(|e| GateError::AttestationInvalid(format!("parse: {e}")))?;
        let measurement = Measurement {
            platform: eat.platform.clone(),
            value_x: eat.value_x.clone(),
        };

        let sig_bytes: [u8; 64] = eat
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| GateError::AttestationInvalid("signature length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        self.vk
            .verify(&dev_signed_bytes(&measurement, &eat.binding), &sig)
            .map_err(|e| GateError::AttestationInvalid(format!("signature: {e}")))?;

        if &eat.binding != expected_binding {
            return Err(GateError::BindingMismatch);
        }
        if !self.allow.contains(&measurement.value_x) {
            return Err(GateError::MeasurementNotAllowed);
        }
        Ok(measurement)
    }
}

/// Apply the gate, then issue. Recomputes the channel binding from the request's
/// actual blinded messages (so a client cannot misreport it), requires the eat
/// to commit to that binding and carry an allowed measurement, and only then
/// blind-signs.
pub fn issue_gated<V: AttestationVerifier>(
    issuer: &crate::Issuer,
    verifier: &V,
    req: &crate::SignRequest,
    eat: &[u8],
) -> Result<crate::SignResponse, GateError> {
    let binding = crate::binding_of(&req.blinded);
    if binding != req.binding {
        return Err(GateError::BindingMismatch);
    }
    let _measurement = verifier.verify(eat, &binding)?;
    issuer
        .blind_sign(req)
        .map_err(|e| GateError::Unknown(e.to_string()))
}
