use chrono::Utc;
use eat_pass_core::gate::Measurement;
use serde::{Deserialize, Serialize};
use unified_quote::tiers::assurance_tier;

use crate::schema::{EvidenceProfile, TrustTier, VerificationPolicy};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckId {
    PolicyNotExpired,
    ProfileMatch,
    BindingOk,
    ReferenceValueMatch,
    RegistryStatus,
    MinTier,
    TierDetailAllowed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppraisalResult {
    pub pass: bool,
    pub policy_id: String,
    pub class_label: String,
    /// Assurance tier from `unified_quote::tiers`: `silicon-cvm`,
    /// `device-attested`, `relay-inherited`, or `software-witness`.
    #[serde(default)]
    pub tier: String,
    /// Finer-grained detail within the tier (e.g. `tpm-ima`, `app-attest`,
    /// `host-attested-guest`, `sev-snp`).
    #[serde(default)]
    pub tier_detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub checks: Vec<(CheckId, bool)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement: Option<Measurement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Normalized claims **after** crypto verification (RFC 9711 attestation-results input).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppraisalClaims {
    pub evidence_profile: EvidenceProfile,
    pub platform: String,
    #[serde(default, with = "crate::schema::hex_option")]
    pub measurement: Option<Vec<u8>>,
    #[serde(default, with = "crate::schema::hex_option")]
    pub app_id_hash: Option<Vec<u8>>,
    /// Channel binding / eat_nonce tie (Hanff et al., CCS 2025 coupled mint).
    pub binding_ok: bool,
    #[serde(default)]
    pub ima_verified: bool,
    #[serde(default)]
    pub registry_status: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum AppraisalError {
    #[error("policy: {0}")]
    Policy(#[from] crate::schema::PolicyError),
}

pub fn appraise(policy: &VerificationPolicy, claims: &AppraisalClaims) -> AppraisalResult {
    let mut checks = Vec::new();
    let class_label = policy.class.name.clone() + "@v" + &policy.class.version.to_string();

    let not_expired = !policy.is_expired(Utc::now());
    checks.push((CheckId::PolicyNotExpired, not_expired));

    let profile_match = claims.evidence_profile == policy.evidence_profile;
    checks.push((CheckId::ProfileMatch, profile_match));

    checks.push((CheckId::BindingOk, claims.binding_ok));

    let identity = claims.measurement.as_ref().or(claims.app_id_hash.as_ref());
    let in_allow = identity.is_some_and(|id| {
        policy
            .allow
            .iter()
            .any(|e| e.measurement.as_ref() == Some(id) || e.app_id_hash.as_ref() == Some(id))
    });
    checks.push((CheckId::ReferenceValueMatch, in_allow));

    let registry_ok = match (&claims.registry_status, policy.registry_minimum) {
        (None, _) => true,
        (Some(s), min) => min.accepts(s),
    };
    checks.push((CheckId::RegistryStatus, registry_ok));

    let (tier, tier_detail) = assurance_tier(&claims.platform, claims.ima_verified);
    let tier_ok = TrustTier::from_label(tier)
        .map(|actual| policy.min_tier.accepts(actual))
        .unwrap_or(false);
    checks.push((CheckId::MinTier, tier_ok));

    let tier_detail_ok = policy.allowed_tier_details.is_empty()
        || policy
            .allowed_tier_details
            .iter()
            .any(|allowed| allowed == &tier_detail);
    checks.push((CheckId::TierDetailAllowed, tier_detail_ok));

    let pass = checks.iter().all(|(_, ok)| *ok);
    let measurement = if pass {
        identity.map(|value_x| {
            Measurement::new(claims.platform.clone(), value_x.clone())
                .with_ima_verified(claims.ima_verified)
        })
    } else {
        None
    };

    let reason = if pass {
        None
    } else {
        Some(fail_reason(&checks))
    };

    AppraisalResult {
        pass,
        policy_id: policy.id.clone(),
        class_label,
        tier: tier.to_string(),
        tier_detail,
        notes: policy.notes.clone(),
        checks,
        measurement,
        reason,
    }
}

fn fail_reason(checks: &[(CheckId, bool)]) -> String {
    checks
        .iter()
        .find(|(_, ok)| !ok)
        .map(|(id, _)| format!("failed check: {id:?}"))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::RegistryMinimum;

    fn sample_policy() -> VerificationPolicy {
        VerificationPolicy {
            version: 1,
            id: "p1".into(),
            valid_until: None,
            evidence_profile: EvidenceProfile::AzureSnpBundle,
            class: crate::schema::ClassSpec {
                name: "accepted".into(),
                version: 1,
            },
            registry_minimum: RegistryMinimum::Recommended,
            min_tier: TrustTier::SoftwareWitness,
            allowed_tier_details: Vec::new(),
            allow: vec![crate::schema::AllowEntry {
                measurement: Some(vec![1u8; 32]),
                app_id_hash: None,
                registry_status: None,
            }],
            require_ima: false,
            boot_aggregates: Vec::new(),
            desktop_tpm_ek_roots: Vec::new(),
            desktop_tpm_activation_pubkeys: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn appraise_pass() {
        let p = sample_policy();
        let c = AppraisalClaims {
            evidence_profile: EvidenceProfile::AzureSnpBundle,
            platform: "sev-snp".into(),
            measurement: Some(vec![1u8; 32]),
            app_id_hash: None,
            binding_ok: true,
            ima_verified: false,
            registry_status: Some("recommended".into()),
        };
        let r = appraise(&p, &c);
        assert!(r.pass);
        assert!(r.measurement.is_some());
        assert_eq!(r.tier, "silicon-cvm");
        assert_eq!(r.tier_detail, "sev-snp");
    }

    #[test]
    fn appraise_binding_fail_closed() {
        let p = sample_policy();
        let c = AppraisalClaims {
            evidence_profile: EvidenceProfile::AzureSnpBundle,
            platform: "sev-snp".into(),
            measurement: Some(vec![1u8; 32]),
            app_id_hash: None,
            binding_ok: false,
            ima_verified: false,
            registry_status: None,
        };
        let r = appraise(&p, &c);
        assert!(!r.pass);
    }

    #[test]
    fn appraise_min_tier_fail_closed() {
        let mut p = sample_policy();
        p.min_tier = TrustTier::SiliconCvm;
        let c = AppraisalClaims {
            evidence_profile: EvidenceProfile::AzureSnpBundle,
            platform: "linux-tpm-client".into(),
            measurement: Some(vec![1u8; 32]),
            app_id_hash: None,
            binding_ok: true,
            ima_verified: true,
            registry_status: None,
        };
        let r = appraise(&p, &c);
        assert!(!r.pass);
        assert!(r.checks.contains(&(CheckId::MinTier, false)));
    }

    #[test]
    fn appraise_tier_detail_allowlist() {
        let mut p = sample_policy();
        p.min_tier = TrustTier::DeviceAttested;
        p.allowed_tier_details = vec!["tpm-ima".into()];
        let c = AppraisalClaims {
            evidence_profile: EvidenceProfile::AzureSnpBundle,
            platform: "linux-tpm-client".into(),
            measurement: Some(vec![1u8; 32]),
            app_id_hash: None,
            binding_ok: true,
            ima_verified: false,
            registry_status: None,
        };
        let r = appraise(&p, &c);
        assert!(!r.pass);
        assert!(r.checks.contains(&(CheckId::TierDetailAllowed, false)));
    }
}
