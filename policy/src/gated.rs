use eat_pass_core::gate::{AttestationVerifier, GateError, Measurement};

use crate::appraise::{appraise, AppraisalClaims, AppraisalResult};
use crate::schema::{EvidenceProfile, VerificationPolicy};

/// Crypto verifier + operator [`VerificationPolicy`] (reference values, expiry).
pub struct PolicyGated<V> {
    inner: V,
    policy: VerificationPolicy,
}

impl<V: AttestationVerifier> PolicyGated<V> {
    pub fn new(inner: V, policy: VerificationPolicy) -> Self {
        Self { inner, policy }
    }

    pub fn policy(&self) -> &VerificationPolicy {
        &self.policy
    }

    pub fn verify_with_appraisal(
        &self,
        eat: &[u8],
        expected_binding: &[u8; 32],
    ) -> Result<(Measurement, AppraisalResult), GateError> {
        let measurement = self.inner.verify(eat, expected_binding)?;
        let identity = measurement.value_x.as_slice();
        let registry_status = registry_status_for(&self.policy, identity);
        let (measurement_claim, app_id_claim) = match self.policy.evidence_profile {
            EvidenceProfile::AndroidKeyAttestation
            | EvidenceProfile::IosAppAttest
            | EvidenceProfile::MacOsAppAttest => (None, Some(measurement.value_x.clone())),
            _ => (Some(measurement.value_x.clone()), None),
        };
        let claims = AppraisalClaims {
            evidence_profile: self.policy.evidence_profile,
            platform: measurement.platform.clone(),
            measurement: measurement_claim,
            app_id_hash: app_id_claim,
            binding_ok: true,
            registry_status,
        };
        let result = appraise(&self.policy, &claims);
        if !result.pass {
            return Err(GateError::AttestationInvalid(
                result.reason.unwrap_or_else(|| "policy denied".into()),
            ));
        }
        Ok((measurement, result))
    }
}

impl<V: AttestationVerifier> AttestationVerifier for PolicyGated<V> {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        self.verify_with_appraisal(eat, expected_binding)
            .map(|(m, _)| m)
    }
}

fn registry_status_for(policy: &VerificationPolicy, identity: &[u8]) -> Option<String> {
    policy
        .allow
        .iter()
        .find(|e| {
            e.measurement.as_deref() == Some(identity) || e.app_id_hash.as_deref() == Some(identity)
        })
        .and_then(|e| e.registry_status.clone())
}
