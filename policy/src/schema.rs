use std::path::Path;

use chrono::{DateTime, Utc};
use eat_pass_core::gate::MeasurementClass;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("policy invalid: {0}")]
    Invalid(String),
}

/// Which attestation wire format this policy applies to (maps to attester `--gate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceProfile {
    /// unified-quote CBOR EAT + platform quote.
    UqEat,
    /// Azure SEV-SNP vTPM bundle JSON.
    AzureSnpBundle,
    /// Attested-TLS leaf on Azure CVM.
    AzureAttestedTls,
    /// Android KeyMint attestation chain JSON.
    AndroidKeyAttestation,
    /// iOS App Attest assertion JSON.
    IosAppAttest,
    /// Linux / Windows TPM2 client quote JSON (`linux-tpm-client` / `windows-tpm-client`).
    DesktopTpmClient,
    /// macOS App Attest assertion JSON.
    MacOsAppAttest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryMinimum {
    Recommended,
    Deprecated,
}

impl RegistryMinimum {
    pub fn accepts(&self, status: &str) -> bool {
        match self {
            Self::Recommended => status == "recommended",
            Self::Deprecated => status == "recommended" || status == "deprecated",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClassSpec {
    pub name: String,
    pub version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllowEntry {
    /// CVM / unified-quote build identity (`value_x` or SNP launch measurement).
    #[serde(default, with = "hex_option")]
    pub measurement: Option<Vec<u8>>,
    /// Mobile app identity (package+cert or team+bundle hash).
    #[serde(default, with = "hex_option")]
    pub app_id_hash: Option<Vec<u8>>,
    /// Expected registry status when `registry_status` is present in appraisal input.
    #[serde(default)]
    pub registry_status: Option<String>,
}

pub(crate) mod hex_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match v {
            None => s.serialize_none(),
            Some(b) => s.serialize_some(&hex::encode(b)),
        }
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            None => Ok(None),
            Some(s) => hex::decode(s.trim()).map(Some).map_err(serde::de::Error::custom),
        }
    }
}

/// Operator policy blob: reference values + validity + class label.
///
/// One file describes one gate profile. See `docs/verification-policy.md`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationPolicy {
    pub version: u32,
    pub id: String,
    #[serde(default)]
    pub valid_until: Option<DateTime<Utc>>,
    pub evidence_profile: EvidenceProfile,
    pub class: ClassSpec,
    #[serde(default = "default_registry_minimum")]
    pub registry_minimum: RegistryMinimum,
    pub allow: Vec<AllowEntry>,
    /// Operator trust-boundary notes (surfaced in logs and appraisal results).
    #[serde(default)]
    pub notes: Option<String>,
}

fn default_registry_minimum() -> RegistryMinimum {
    RegistryMinimum::Recommended
}

impl VerificationPolicy {
    pub fn from_json_bytes(b: &[u8]) -> Result<Self, PolicyError> {
        let p: Self = serde_json::from_slice(b)?;
        p.validate()?;
        Ok(p)
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let b = std::fs::read(path)?;
        Self::from_json_bytes(&b)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != 1 {
            return Err(PolicyError::Invalid(format!(
                "unsupported policy version {}",
                self.version
            )));
        }
        if self.id.is_empty() {
            return Err(PolicyError::Invalid("id must be non-empty".into()));
        }
        if self.class.name.is_empty() {
            return Err(PolicyError::Invalid("class.name must be non-empty".into()));
        }
        if self.allow.is_empty() {
            return Err(PolicyError::Invalid("allow must not be empty".into()));
        }
        for (i, e) in self.allow.iter().enumerate() {
            let has_m = e.measurement.as_ref().is_some_and(|m| !m.is_empty());
            let has_a = e.app_id_hash.as_ref().is_some_and(|m| !m.is_empty());
            if has_m == has_a {
                return Err(PolicyError::Invalid(format!(
                    "allow[{i}]: set exactly one of measurement or app_id_hash"
                )));
            }
            match self.evidence_profile {
                EvidenceProfile::AndroidKeyAttestation
                | EvidenceProfile::IosAppAttest
                | EvidenceProfile::MacOsAppAttest => {
                    if !has_a {
                        return Err(PolicyError::Invalid(format!(
                            "allow[{i}]: app-attest profile requires app_id_hash only"
                        )));
                    }
                }
                EvidenceProfile::DesktopTpmClient => {
                    if !has_m {
                        return Err(PolicyError::Invalid(format!(
                            "allow[{i}]: desktop-tpm profile requires measurement (build_id_hash) only"
                        )));
                    }
                }
                _ => {
                    if !has_m {
                        return Err(PolicyError::Invalid(format!(
                            "allow[{i}]: CVM profile requires measurement only"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.valid_until.is_some_and(|u| now > u)
    }

    /// Build the anonymity-set allowlist consumed by [`MeasurementClass`].
    pub fn measurement_class(&self) -> MeasurementClass {
        let accepted: Vec<Vec<u8>> = self
            .allow
            .iter()
            .filter_map(|e| e.measurement.clone().or_else(|| e.app_id_hash.clone()))
            .collect();
        MeasurementClass::new(self.class.name.clone(), self.class.version, accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_cvm_policy() {
        let j = r#"{
          "version": 1,
          "id": "test",
          "evidence_profile": "azure-snp-bundle",
          "class": { "name": "accepted-builds", "version": 1 },
          "allow": [{ "measurement": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" }]
        }"#;
        let p = VerificationPolicy::from_json_bytes(j.as_bytes()).unwrap();
        assert_eq!(p.allow.len(), 1);
        assert_eq!(p.measurement_class().len(), 1);
    }
}
