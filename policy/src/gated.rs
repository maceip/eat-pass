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
            ima_verified: measurement.ima_verified,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appraise::CheckId;
    use crate::schema::{
        AllowEntry, ClassSpec, EvidenceProfile, RegistryMinimum, TrustTier, VerificationPolicy,
    };

    #[derive(Clone)]
    struct StaticVerifier {
        binding: [u8; 32],
        measurement: Measurement,
    }

    impl AttestationVerifier for StaticVerifier {
        fn verify(
            &self,
            _eat: &[u8],
            expected_binding: &[u8; 32],
        ) -> Result<Measurement, GateError> {
            if expected_binding != &self.binding {
                return Err(GateError::BindingMismatch);
            }
            Ok(self.measurement.clone())
        }
    }

    struct ResultShapeCase {
        verifier_name: &'static str,
        profile: EvidenceProfile,
        platform: &'static str,
        ima_verified: bool,
        identity_len: usize,
        tier: &'static str,
        tier_detail: &'static str,
        identity_is_app_id: bool,
    }

    #[test]
    fn active_verifier_results_match_eat_pass_result_shape() {
        let cases = [
            ResultShapeCase {
                verifier_name: "UqVerifier/sev-snp",
                profile: EvidenceProfile::UqEat,
                platform: "sev-snp",
                ima_verified: false,
                identity_len: 48,
                tier: "silicon-cvm",
                tier_detail: "sev-snp",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "UqVerifier/nitro",
                profile: EvidenceProfile::UqEat,
                platform: "nitro",
                ima_verified: false,
                identity_len: 48,
                tier: "silicon-cvm",
                tier_detail: "nitro",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "UqVerifier/tdx",
                profile: EvidenceProfile::UqEat,
                platform: "tdx",
                ima_verified: false,
                identity_len: 48,
                tier: "silicon-cvm",
                tier_detail: "tdx",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "AzureUqVerifier",
                profile: EvidenceProfile::AzureSnpBundle,
                platform: "azure-sev-snp-vtpm",
                ima_verified: false,
                identity_len: 48,
                tier: "silicon-cvm",
                tier_detail: "azure-sev-snp-vtpm",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "AzureTlsVerifier",
                profile: EvidenceProfile::AzureAttestedTls,
                platform: "azure-sev-snp-vtpm",
                ima_verified: false,
                identity_len: 48,
                tier: "silicon-cvm",
                tier_detail: "azure-sev-snp-vtpm",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "DesktopTpmVerifier/linux",
                profile: EvidenceProfile::DesktopTpmClient,
                platform: "linux-tpm-client",
                ima_verified: true,
                identity_len: 32,
                tier: "device-attested",
                tier_detail: "tpm-ima",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "DesktopTpmVerifier/windows",
                profile: EvidenceProfile::DesktopTpmClient,
                platform: "windows-tpm-client",
                ima_verified: false,
                identity_len: 32,
                tier: "device-attested",
                tier_detail: "tpm-channel-bound",
                identity_is_app_id: false,
            },
            ResultShapeCase {
                verifier_name: "AndroidKeyAttestationVerifier",
                profile: EvidenceProfile::AndroidKeyAttestation,
                platform: "android-key-attestation",
                ima_verified: false,
                identity_len: 32,
                tier: "device-attested",
                tier_detail: "app-attest",
                identity_is_app_id: true,
            },
            ResultShapeCase {
                verifier_name: "IosAppAttestVerifier",
                profile: EvidenceProfile::IosAppAttest,
                platform: "ios-app-attest",
                ima_verified: false,
                identity_len: 32,
                tier: "device-attested",
                tier_detail: "app-attest",
                identity_is_app_id: true,
            },
            ResultShapeCase {
                verifier_name: "MacOsAppAttestVerifier",
                profile: EvidenceProfile::MacOsAppAttest,
                platform: "macos-app-attest",
                ima_verified: false,
                identity_len: 32,
                tier: "device-attested",
                tier_detail: "app-attest",
                identity_is_app_id: true,
            },
        ];

        let binding = [0xB7; 32];
        for (i, case) in cases.iter().enumerate() {
            let identity = vec![i as u8 + 1; case.identity_len];
            let policy = policy_for_case(case, identity.clone());
            policy
                .validate()
                .unwrap_or_else(|e| panic!("{} policy: {e}", case.verifier_name));
            let verifier = StaticVerifier {
                binding,
                measurement: Measurement::new(case.platform, identity.clone())
                    .with_ima_verified(case.ima_verified),
            };
            let gate = PolicyGated::new(verifier, policy);
            let (measurement, appraisal) = gate
                .verify_with_appraisal(b"verified-evidence", &binding)
                .unwrap_or_else(|e| panic!("{} appraisal: {e}", case.verifier_name));

            assert_eq!(
                measurement.platform, case.platform,
                "{}",
                case.verifier_name
            );
            assert_eq!(measurement.value_x, identity, "{}", case.verifier_name);
            assert_eq!(
                measurement.ima_verified, case.ima_verified,
                "{}",
                case.verifier_name
            );
            assert!(appraisal.pass, "{}", case.verifier_name);
            assert_eq!(appraisal.tier, case.tier, "{}", case.verifier_name);
            assert_eq!(
                appraisal.tier_detail, case.tier_detail,
                "{}",
                case.verifier_name
            );
            assert_eq!(
                appraisal
                    .measurement
                    .as_ref()
                    .map(|m| (&m.platform, &m.value_x)),
                Some((&case.platform.to_string(), &identity)),
                "{}",
                case.verifier_name
            );
            assert_check(&appraisal, CheckId::BindingOk, case.verifier_name);
            assert_check(&appraisal, CheckId::ReferenceValueMatch, case.verifier_name);
            assert_check(&appraisal, CheckId::MinTier, case.verifier_name);
            assert_check(&appraisal, CheckId::TierDetailAllowed, case.verifier_name);

            let wrong_binding = [0xC8; 32];
            assert_eq!(
                gate.verify(b"verified-evidence", &wrong_binding),
                Err(GateError::BindingMismatch),
                "{}",
                case.verifier_name
            );
        }
    }

    fn policy_for_case(case: &ResultShapeCase, identity: Vec<u8>) -> VerificationPolicy {
        VerificationPolicy {
            version: 1,
            id: format!("{}-contract", case.verifier_name),
            valid_until: None,
            evidence_profile: case.profile,
            class: ClassSpec {
                name: "accepted-identities".into(),
                version: 1,
            },
            registry_minimum: RegistryMinimum::Recommended,
            min_tier: TrustTier::from_label(case.tier).unwrap(),
            allowed_tier_details: vec![case.tier_detail.into()],
            allow: vec![if case.identity_is_app_id {
                AllowEntry {
                    measurement: None,
                    app_id_hash: Some(identity),
                    registry_status: Some("recommended".into()),
                }
            } else {
                AllowEntry {
                    measurement: Some(identity),
                    app_id_hash: None,
                    registry_status: Some("recommended".into()),
                }
            }],
            require_ima: false,
            boot_aggregates: Vec::new(),
            desktop_tpm_ek_roots: if case.profile == EvidenceProfile::DesktopTpmClient {
                vec!["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into()]
            } else {
                Vec::new()
            },
            desktop_tpm_activation_pubkeys: if case.profile == EvidenceProfile::DesktopTpmClient {
                vec!["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into()]
            } else {
                Vec::new()
            },
            notes: None,
        }
    }

    fn assert_check(result: &AppraisalResult, id: CheckId, label: &str) {
        assert!(
            result.checks.iter().any(|(check, ok)| *check == id && *ok),
            "{label}: missing successful {id:?}"
        );
    }
}
