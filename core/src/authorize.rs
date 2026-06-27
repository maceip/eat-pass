//! Split attester / issuer trust boundary (A.2).
//!
//! The **attester** verifies hardware attestation and returns a short-lived,
//! ed25519-signed [`IssuanceAuthorization`]. The **issuer** holds only the
//! blind-RSA signing key and mints tokens on presentation of a valid
//! authorization — it never sees or judges raw EAT bytes.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::gate::{AttestationVerifier, GateError};
use crate::ratelimit::{RateLimitError, RateLimiter};

/// Wire version for [`IssuanceAuthorization`]. Bump on breaking changes.
pub const AUTHORIZATION_VERSION: u32 = 1;

/// Default authorization lifetime (seconds) when the attester does not override.
pub const DEFAULT_AUTHORIZATION_TTL_SECS: u64 = 60;

const AUTH_DOMAIN: &[u8] = b"eat-pass/v0/issuance-auth\0";

/// Signed payload authorizing one blind-sign batch at the issuer.
///
/// The issuer learns only `rate_limit_id` (a hash of platform + value_x), not
/// the raw build measurement — preserving anonymity at the issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuanceAuthorization {
    pub version: u32,
    #[serde(with = "crate::serdehelp::hex32")]
    pub binding: [u8; 32],
    #[serde(with = "crate::serdehelp::b64vec")]
    pub rate_limit_id: Vec<u8>,
    pub policy_label: String,
    pub max_batch: u32,
    pub exp: u64,
    pub iat: u64,
    #[serde(with = "crate::serdehelp::b64vec")]
    pub sig: Vec<u8>,
}

impl IssuanceAuthorization {
    /// Canonical signed bytes (everything except `sig`).
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            AUTH_DOMAIN.len()
                + 4
                + 32
                + self.rate_limit_id.len()
                + self.policy_label.len()
                + 12,
        );
        v.extend_from_slice(AUTH_DOMAIN);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.binding);
        v.extend_from_slice(&(self.rate_limit_id.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.rate_limit_id);
        v.extend_from_slice(&(self.policy_label.len() as u32).to_le_bytes());
        v.extend_from_slice(self.policy_label.as_bytes());
        v.extend_from_slice(&self.max_batch.to_le_bytes());
        v.extend_from_slice(&self.exp.to_le_bytes());
        v.extend_from_slice(&self.iat.to_le_bytes());
        v
    }

    /// Verify the attester signature and time bounds.
    pub fn verify(&self, attester_pub: &VerifyingKey, now: u64) -> Result<(), GateError> {
        if self.version != AUTHORIZATION_VERSION {
            return Err(GateError::AttestationInvalid(format!(
                "authorization version {} unsupported (want {AUTHORIZATION_VERSION})",
                self.version
            )));
        }
        if self.max_batch == 0 {
            return Err(GateError::AttestationInvalid(
                "authorization max_batch must be non-zero".into(),
            ));
        }
        if now > self.exp {
            return Err(GateError::AttestationInvalid(
                "authorization expired".into(),
            ));
        }
        let sig_bytes: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| GateError::AttestationInvalid("authorization sig length".into()))?;
        let sig = Signature::from_bytes(&sig_bytes);
        attester_pub
            .verify(&self.signed_bytes(), &sig)
            .map_err(|e| GateError::AttestationInvalid(format!("authorization sig: {e}")))?;
        Ok(())
    }
}

/// Holds the attester signing key and attestation policy verifier.
pub struct Authorizer<V> {
    signer: SigningKey,
    verifier: V,
    ttl_secs: u64,
    policy_label: String,
}

impl<V: AttestationVerifier> Authorizer<V> {
    pub fn new(
        seed: [u8; 32],
        verifier: V,
        policy_label: impl Into<String>,
        ttl_secs: u64,
    ) -> Self {
        Self {
            signer: SigningKey::from_bytes(&seed),
            verifier,
            policy_label: policy_label.into(),
            ttl_secs,
        }
    }

    pub fn verifying_key(&self) -> [u8; 32] {
        self.signer.verifying_key().to_bytes()
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    /// Verify `eat` and return a signed, short-lived authorization for `binding`.
    pub fn authorize(
        &self,
        eat: &[u8],
        binding: &[u8; 32],
        max_batch: u32,
        now: u64,
    ) -> Result<IssuanceAuthorization, GateError> {
        if max_batch == 0 {
            return Err(GateError::AttestationInvalid(
                "max_batch must be non-zero".into(),
            ));
        }
        let measurement = self.verifier.verify(eat, binding)?;
        let mut auth = IssuanceAuthorization {
            version: AUTHORIZATION_VERSION,
            binding: *binding,
            rate_limit_id: measurement.rate_limit_id(),
            policy_label: self.policy_label.clone(),
            max_batch,
            exp: now.saturating_add(self.ttl_secs),
            iat: now,
            sig: Vec::new(),
        };
        let sig = self.signer.sign(&auth.signed_bytes());
        auth.sig = sig.to_bytes().to_vec();
        Ok(auth)
    }
}

/// Parse a pinned attester verifying key (32 raw bytes, hex-encoded).
pub fn attester_pubkey_from_hex(hex_str: &str) -> Result<VerifyingKey, GateError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| GateError::AttestationInvalid(format!("attester pub hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| GateError::AttestationInvalid("attester pub must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| GateError::AttestationInvalid(format!("attester pub: {e}")))
}

/// Issuer path: verify authorization, enforce quota, blind-sign.
pub fn issue_authorized_with_limit<R: RateLimiter>(
    issuer: &crate::Issuer,
    attester_pub: &VerifyingKey,
    req: &crate::SignRequest,
    auth: &IssuanceAuthorization,
    limiter: &R,
    now: u64,
) -> Result<crate::SignResponse, GateError> {
    auth.verify(attester_pub, now)?;

    let binding = crate::binding_of(&req.blinded);
    if binding != req.binding {
        return Err(GateError::BindingMismatch);
    }
    if binding != auth.binding {
        return Err(GateError::BindingMismatch);
    }
    let batch = req.blinded.len() as u32;
    if batch > auth.max_batch {
        return Err(GateError::AttestationInvalid(format!(
            "batch size {batch} exceeds authorization max_batch {}",
            auth.max_batch
        )));
    }

    limiter
        .try_consume(&auth.rate_limit_id, batch)
        .map_err(|e| match e {
            RateLimitError::Exceeded => GateError::QuotaExceeded,
            RateLimitError::Backend(m) => GateError::Unknown(format!("rate-limit backend: {m}")),
        })?;

    issuer
        .blind_sign(req)
        .map_err(|e| GateError::Unknown(e.to_string()))
}

#[cfg(any(test, feature = "dev-sim"))]
pub mod dev {
    use super::*;
    use crate::gate::{DevAttester, DevVerifier, MeasurementClass};

    /// Build a matched dev attester + authorizer from one ed25519 seed.
    pub fn from_seed(
        seed: [u8; 32],
        allow: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<(DevAttester, Authorizer<DevVerifier>), GateError> {
        let attester = DevAttester::from_seed(seed);
        let class = MeasurementClass::new("default", 1, allow);
        let verifier = DevVerifier::new_for_class(attester.verifying_key(), class)?;
        let authorizer = Authorizer::new(
            seed,
            verifier,
            "default@v1",
            DEFAULT_AUTHORIZATION_TTL_SECS,
        );
        Ok((attester, authorizer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{DevAttester, DevVerifier, Measurement};
    use crate::ratelimit::InMemoryRateLimiter;
    use crate::{Client, Issuer, TokenChallenge};

    fn now() -> u64 {
        1_700_000_000
    }

    #[test]
    fn split_authorize_then_issue() {
        let seed = [7u8; 32];
        let attester = DevAttester::from_seed(seed);
        let value_x = vec![7u8; 32];
        let measurement = Measurement::new("dev", value_x.clone());
        let verifier = DevVerifier::new(attester.verifying_key(), [value_x]).unwrap();
        let authorizer = Authorizer::new(
            seed,
            verifier,
            "default@v1",
            DEFAULT_AUTHORIZATION_TTL_SECS,
        );
        let attester_pub =
            attester_pubkey_from_hex(&hex::encode(attester.verifying_key())).unwrap();

        let issuer = Issuer::generate(1, 2048).unwrap();
        let pk = issuer.public();
        let challenge = TokenChallenge::new("issuer", "origin");
        let (req, pending) = Client::begin(&pk, &challenge, 2).unwrap();
        let binding = req.binding();
        let eat = attester.attest(&measurement, &binding);

        let auth = authorizer.authorize(&eat, &binding, 2, now()).unwrap();
        let limiter = InMemoryRateLimiter::new(64, 3600);
        let resp = issue_authorized_with_limit(
            &issuer,
            &attester_pub,
            &req,
            &auth,
            &limiter,
            now(),
        )
        .unwrap();
        assert_eq!(resp.blind_sigs.len(), 2);
        pending.finalize(&pk, &resp).unwrap();
    }

    #[test]
    fn expired_authorization_rejected() {
        let seed = [1u8; 32];
        let attester = DevAttester::from_seed(seed);
        let value_x = vec![1u8; 32];
        let verifier = DevVerifier::new(attester.verifying_key(), [value_x.clone()]).unwrap();
        let authorizer = Authorizer::new(seed, verifier, "default@v1", 1);
        let attester_pub =
            attester_pubkey_from_hex(&hex::encode(attester.verifying_key())).unwrap();
        let measurement = Measurement::new("dev", value_x);
        let binding = [0u8; 32];
        let eat = attester.attest(&measurement, &binding);
        let auth = authorizer.authorize(&eat, &binding, 1, now()).unwrap();

        let issuer = Issuer::generate(1, 2048).unwrap();
        let pk = issuer.public();
        let challenge = TokenChallenge::new("i", "o");
        let (req, _pending) = Client::begin(&pk, &challenge, 1).unwrap();
        let limiter = InMemoryRateLimiter::new(64, 3600);
        let err = issue_authorized_with_limit(
            &issuer,
            &attester_pub,
            &req,
            &auth,
            &limiter,
            now() + 10,
        )
        .unwrap_err();
        assert!(matches!(err, GateError::AttestationInvalid(_)));
    }
}
