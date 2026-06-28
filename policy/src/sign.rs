use std::path::{Path, PathBuf};

use base64::Engine;
use faest::FAEST128fVerifyingKey;

use crate::faest_sig::{self, sign, signing_key_from_seed, verify};
use crate::schema::{PolicyError, VerificationPolicy};

/// Sidecar path: `policy.json` → `policy.json.sig` (base64 FAEST-128f signature).
pub fn sidecar_path(policy_path: &Path) -> PathBuf {
    let mut p = policy_path.to_path_buf();
    let name = policy_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("policy.json");
    p.set_file_name(format!("{name}.sig"));
    p
}

pub fn load_verified(
    policy_path: &Path,
    trusted_pubs: &[FAEST128fVerifyingKey],
) -> Result<VerificationPolicy, PolicyError> {
    let bytes = std::fs::read(policy_path)?;
    let policy = VerificationPolicy::from_json_bytes(&bytes)?;

    if trusted_pubs.is_empty() {
        return Ok(policy);
    }

    let sig_path = sidecar_path(policy_path);
    let sig_b64 = std::fs::read_to_string(&sig_path).map_err(|e| {
        PolicyError::Invalid(format!(
            "policy sidecar {} required when trusted keys are configured: {e}",
            sig_path.display()
        ))
    })?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64.trim())
        .map_err(|e| PolicyError::Invalid(format!("policy sidecar bad base64: {e}")))?;

    let verified = trusted_pubs
        .iter()
        .any(|vk| verify(vk, &bytes, &sig_bytes).is_ok());
    if !verified {
        return Err(PolicyError::Invalid(
            "policy sidecar signature does not verify under any trusted key".into(),
        ));
    }
    Ok(policy)
}

pub fn trusted_pubs_from_env() -> Result<Vec<FAEST128fVerifyingKey>, PolicyError> {
    let Ok(raw) = std::env::var("EATPASS_POLICY_TRUSTED_PUB") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (i, hex_str) in raw.split(',').enumerate() {
        let hex_str = hex_str.trim();
        if hex_str.is_empty() {
            continue;
        }
        out.push(
            faest_sig::verifying_key_from_hex(hex_str).map_err(|e| {
                PolicyError::Invalid(format!("EATPASS_POLICY_TRUSTED_PUB[{i}]: {e}"))
            })?,
        );
    }
    Ok(out)
}

pub fn signing_key_from_env() -> Result<faest::FAEST128fSigningKey, PolicyError> {
    let hex_str = std::env::var("EATPASS_POLICY_SIGNING_SEED").map_err(|_| {
        PolicyError::Invalid(
            "EATPASS_POLICY_SIGNING_SEED required (64 hex chars) to sign policy sidecars".into(),
        )
    })?;
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| PolicyError::Invalid(format!("EATPASS_POLICY_SIGNING_SEED bad hex: {e}")))?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        PolicyError::Invalid("EATPASS_POLICY_SIGNING_SEED must be 32 bytes".into())
    })?;
    signing_key_from_seed(seed).map_err(|e| PolicyError::Invalid(e.to_string()))
}

pub fn sign_policy_file(policy_path: &Path) -> Result<PathBuf, PolicyError> {
    let bytes = std::fs::read(policy_path)?;
    VerificationPolicy::from_json_bytes(&bytes)?;
    let sk = signing_key_from_env()?;
    let sig = sign(&sk, &bytes);
    let out = sidecar_path(policy_path);
    std::fs::write(
        &out,
        base64::engine::general_purpose::STANDARD.encode(sig),
    )?;
    Ok(out)
}
