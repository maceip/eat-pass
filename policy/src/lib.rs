//! Operator-controlled verification policy for eat-pass.
//!
//! Crypto verification lives in `eat-pass-gate` / `unified-quote`; this crate
//! holds the **appraisal policy** layer (reference values, validity window,
//! registry status) described in IETF RATS CoRIM and RFC 9711 attestation
//! results.

mod appraise;
mod diff;
mod gated;
mod schema;
mod sign;

pub use appraise::{appraise, AppraisalClaims, AppraisalError, AppraisalResult, CheckId};
pub use diff::{diff, PolicyDiff};
pub use gated::PolicyGated;
pub use schema::{
    EvidenceProfile, PolicyError, RegistryMinimum, VerificationPolicy,
};
pub use sign::{
    load_verified, sidecar_path, sign_policy_file, signing_key_from_env, trusted_pubs_from_env,
};

use chrono::Utc;

/// Map attester `--gate` backend to policy `evidence_profile`.
pub fn evidence_profile_for_gate(gate: &str) -> Result<EvidenceProfile, PolicyError> {
    match gate {
        "uq" => Ok(EvidenceProfile::UqEat),
        "azure" => Ok(EvidenceProfile::AzureSnpBundle),
        "azure-tls" => Ok(EvidenceProfile::AzureAttestedTls),
        "android-key" | "android" => Ok(EvidenceProfile::AndroidKeyAttestation),
        "ios-app-attest" | "ios" => Ok(EvidenceProfile::IosAppAttest),
        "desktop-tpm" | "linux-tpm" | "windows-tpm" => Ok(EvidenceProfile::DesktopTpmClient),
        "macos-app-attest" | "macos" => Ok(EvidenceProfile::MacOsAppAttest),
        other => Err(PolicyError::Invalid(format!("unknown gate '{other}'"))),
    }
}

/// Load and verify policy; fail if expired or profile mismatches gate.
pub fn load_for_attester(
    path: &std::path::Path,
    gate: &str,
    trusted_pubs: &[faest::FAEST128fVerificationKey],
) -> Result<VerificationPolicy, PolicyError> {
    let policy = load_verified(path, trusted_pubs)?;
    if policy.is_expired(Utc::now()) {
        return Err(PolicyError::Invalid(format!(
            "policy {} expired (valid_until={:?})",
            policy.id, policy.valid_until
        )));
    }
    let want = evidence_profile_for_gate(gate)?;
    if policy.evidence_profile != want {
        return Err(PolicyError::Invalid(format!(
            "policy evidence_profile {:?} does not match --gate {gate} ({want:?})",
            policy.evidence_profile
        )));
    }
    Ok(policy)
}
