//! The attestation gate: issuance is allowed only for a request that carries a
//! valid attestation (an "eat") which commits to the request's channel binding
//! and whose measurement the issuer accepts.
//!
//! [`AttestationVerifier`] is the seam. This module ships [`DevVerifier`] (an
//! ed25519-signed dev statement) so the protocol is testable on every platform
//! with no TEE hardware. The real `unified-quote` EAT verifier lives in the
//! `eat-pass-gate` crate (milestone m2).
//!
//! ## Trust boundary: attester vs. issuer (A.2)
//!
//! Conceptually there are two roles:
//! - the **attester/verifier** decides *eligibility* (is this a valid eat from
//!   an accepted build, bound to this request?), and
//! - the **issuer** holds the signing key and *mints* the blind signature.
//!
//! [`issue_gated`] runs both in one call for unit tests and legacy callers.
//! Production deployments split the roles: an **attester** verifies EATs and
//! returns a short-lived [`crate::authorize::IssuanceAuthorization`]; the
//! **issuer** blind-signs only on a valid authorization (see
//! [`crate::authorize::issue_authorized_with_limit`]).

use std::collections::HashSet;

#[cfg(any(test, feature = "dev-sim"))]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ratelimit::{RateLimitError, RateLimiter};

#[cfg(any(test, feature = "dev-sim"))]
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

    /// A coarse, privacy-preserving rate-limit identity for this measurement
    /// (E.7). It is a hash of the *build*, never an identity — so the limiter
    /// caps farming per accepted build per epoch without deanonymizing anyone.
    pub fn rate_limit_id(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"eat-pass/v0/ratelimit-id\0");
        h.update(self.platform.as_bytes());
        h.update([0]);
        h.update(&self.value_x);
        h.finalize().to_vec()
    }
}

/// A named set of accepted measurements — the anonymity set (E.5).
///
/// Gating on a *class* (e.g. "accepted-builds-v1") rather than an exact
/// `value_x` widens the anonymity set to everyone running any build in the
/// class. The class `version` lets the accepted set roll forward without
/// silently changing what a given class name means. Paired with
/// [`crate::pbrsa`], the class name becomes auditable public metadata on the
/// issued token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasurementClass {
    pub name: String,
    pub version: u32,
    accepted: HashSet<Vec<u8>>,
}

impl MeasurementClass {
    pub fn new(
        name: impl Into<String>,
        version: u32,
        accepted: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        Self {
            name: name.into(),
            version,
            accepted: accepted.into_iter().collect(),
        }
    }

    pub fn contains(&self, value_x: &[u8]) -> bool {
        self.accepted.contains(value_x)
    }

    /// The policy-class label bound as public metadata (`name@vN`).
    pub fn policy_label(&self) -> String {
        format!("{}@v{}", self.name, self.version)
    }

    pub fn len(&self) -> usize {
        self.accepted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.accepted.is_empty()
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

/// Wraps any [`AttestationVerifier`] to additionally enforce a
/// [`MeasurementClass`] (the anonymity set, E.5).
///
/// Some verifiers *authenticate* an attestation but do not themselves decide
/// which builds are acceptable — notably the real `unified-quote` verifier,
/// which proves a quote is genuine and extracts its `value_x` but leaves the
/// allowlist policy to the caller. `ClassGated` adds that policy: it runs the
/// inner verifier, then rejects with [`GateError::MeasurementNotAllowed`] unless
/// the extracted measurement is in `class`. (`DevVerifier` already gates on a
/// class internally, so it does not need wrapping.)
pub struct ClassGated<V> {
    inner: V,
    class: MeasurementClass,
}

impl<V> ClassGated<V> {
    pub fn new(inner: V, class: MeasurementClass) -> Self {
        Self { inner, class }
    }

    pub fn class(&self) -> &MeasurementClass {
        &self.class
    }
}

impl<V: AttestationVerifier> AttestationVerifier for ClassGated<V> {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        let m = self.inner.verify(eat, expected_binding)?;
        if !self.class.contains(&m.value_x) {
            return Err(GateError::MeasurementNotAllowed);
        }
        Ok(m)
    }
}

#[cfg(any(test, feature = "dev-sim"))]
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
#[cfg(any(test, feature = "dev-sim"))]
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
///
/// Compiled only under `--features dev-sim` (and in tests). It is never present
/// in a shipped binary, so issuance can never be gated on a dev statement in
/// production — there is no flag, env var, or default that enables it.
#[cfg(any(test, feature = "dev-sim"))]
pub struct DevAttester {
    sk: SigningKey,
}

#[cfg(any(test, feature = "dev-sim"))]
impl DevAttester {
    pub fn generate() -> Result<Self, GateError> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| GateError::Unknown(e.to_string()))?;
        Ok(Self::from_seed(seed))
    }

    /// Reconstruct an attester from a 32-byte ed25519 seed. Lets a caller persist
    /// the seed (e.g. a CLI flag/env) and recreate the same attester identity —
    /// the dev stand-in for "the same TEE instance produced this eat".
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(&seed),
        }
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

/// Verifies dev eats against a trusted attester key and an accepted
/// [`MeasurementClass`] (the anonymity set, E.5).
///
/// Compiled only under `--features dev-sim` (and in tests) — see [`DevAttester`].
#[cfg(any(test, feature = "dev-sim"))]
pub struct DevVerifier {
    vk: VerifyingKey,
    class: MeasurementClass,
}

#[cfg(any(test, feature = "dev-sim"))]
impl DevVerifier {
    /// Build a verifier from a flat allowlist (an anonymous class "default@v1").
    pub fn new(
        attester_key: [u8; 32],
        allow: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, GateError> {
        Self::new_for_class(attester_key, MeasurementClass::new("default", 1, allow))
    }

    /// Build a verifier gated on a named measurement class.
    pub fn new_for_class(
        attester_key: [u8; 32],
        class: MeasurementClass,
    ) -> Result<Self, GateError> {
        let vk = VerifyingKey::from_bytes(&attester_key)
            .map_err(|e| GateError::AttestationInvalid(e.to_string()))?;
        Ok(Self { vk, class })
    }

    /// The accepted measurement class (anonymity set).
    pub fn class(&self) -> &MeasurementClass {
        &self.class
    }
}

#[cfg(any(test, feature = "dev-sim"))]
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
        if !self.class.contains(&measurement.value_x) {
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

/// Like [`issue_gated`] but enforces a per-attestation issuance quota (E.7)
/// before signing. The limiter is keyed on [`Measurement::rate_limit_id`] — a
/// hash of the build, never an identity — and charged the batch size.
pub fn issue_gated_with_limit<V: AttestationVerifier, R: RateLimiter>(
    issuer: &crate::Issuer,
    verifier: &V,
    req: &crate::SignRequest,
    eat: &[u8],
    limiter: &R,
) -> Result<crate::SignResponse, GateError> {
    let binding = crate::binding_of(&req.blinded);
    if binding != req.binding {
        return Err(GateError::BindingMismatch);
    }
    let measurement = verifier.verify(eat, &binding)?;
    limiter
        .try_consume(&measurement.rate_limit_id(), req.blinded.len() as u32)
        .map_err(|e| match e {
            RateLimitError::Exceeded => GateError::QuotaExceeded,
            // Fail-closed: a backend outage denies issuance rather than letting
            // an un-counted batch through.
            RateLimitError::Backend(m) => GateError::Unknown(format!("rate-limit backend: {m}")),
        })?;
    issuer
        .blind_sign(req)
        .map_err(|e| GateError::Unknown(e.to_string()))
}

/// Gate + issue under the partially-blind path (E.5 + E.6): verify the eat,
/// confirm its measurement is in `verifier`'s accepted class, then blind-sign
/// the blinded messages under that class as auditable public metadata. The
/// origin later sees only the class, never the exact `value_x`.
pub fn issue_gated_pbrsa<V: AttestationVerifier>(
    pb_issuer: &crate::pbrsa::PbIssuer,
    verifier: &V,
    blinded: &[blind_rsa_signatures::BlindMessage],
    binding: &[u8; 32],
    class: &MeasurementClass,
    eat: &[u8],
) -> Result<Vec<blind_rsa_signatures::BlindSignature>, GateError> {
    let recomputed = crate::binding_of(blinded);
    if &recomputed != binding {
        return Err(GateError::BindingMismatch);
    }
    let measurement = verifier.verify(eat, binding)?;
    if !class.contains(&measurement.value_x) {
        return Err(GateError::MeasurementNotAllowed);
    }
    let policy = crate::pbrsa::PolicyClass::new(class.policy_label());
    pb_issuer
        .blind_sign(blinded, &policy)
        .map_err(|e| GateError::Unknown(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verifier that authenticates nothing — it just returns a fixed
    /// measurement. Stands in for an authenticating-but-not-allowlisting
    /// verifier (like the real unified-quote one) so we can test `ClassGated`.
    struct FixedMeasurement(Measurement);
    impl AttestationVerifier for FixedMeasurement {
        fn verify(&self, _eat: &[u8], _binding: &[u8; 32]) -> Result<Measurement, GateError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn class_gated_allows_in_class_rejects_out_of_class() {
        let in_class = vec![1u8; 32];
        let out_class = vec![9u8; 32];
        let class = MeasurementClass::new("accepted", 2, [in_class.clone()]);

        let ok = ClassGated::new(
            FixedMeasurement(Measurement::new("sev-snp", in_class.clone())),
            class.clone(),
        );
        assert!(ok.verify(b"", &[0u8; 32]).is_ok());
        assert_eq!(ok.class().policy_label(), "accepted@v2");

        let bad = ClassGated::new(
            FixedMeasurement(Measurement::new("sev-snp", out_class)),
            class,
        );
        assert_eq!(
            bad.verify(b"", &[0u8; 32]),
            Err(GateError::MeasurementNotAllowed)
        );
    }
}
