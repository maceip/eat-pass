//! `eat-pass policy validate|simulate|diff|sign` — human/agent policy tooling.

use std::path::PathBuf;

use eat_pass_policy::{
    appraise, diff, sign_policy_file, AppraisalClaims, VerificationPolicy,
};

pub fn validate(path: &PathBuf) -> anyhow::Result<()> {
    let policy = VerificationPolicy::from_json_file(path)?;
    let class = policy.measurement_class();
    println!("OK  policy id={} profile={:?}", policy.id, policy.evidence_profile);
    println!("    class={} allow={}", class.policy_label(), class.len());
    if let Some(until) = policy.valid_until {
        println!("    valid_until={until}");
    }
    if let Some(n) = &policy.notes {
        println!("    notes={n}");
    }
    Ok(())
}

pub fn simulate(policy_path: &PathBuf, claims_path: &PathBuf) -> anyhow::Result<()> {
    let policy = VerificationPolicy::from_json_file(policy_path)?;
    let claims_json = std::fs::read(claims_path)?;
    let claims: AppraisalClaims = serde_json::from_slice(&claims_json)?;
    let result = appraise(&policy, &claims);
    println!("{}", serde_json::to_string_pretty(&result)?);
    if !result.pass {
        std::process::exit(1);
    }
    Ok(())
}

pub fn diff_policies(left: &PathBuf, right: &PathBuf) -> anyhow::Result<()> {
    let left_p = VerificationPolicy::from_json_file(left)?;
    let right_p = VerificationPolicy::from_json_file(right)?;
    let d = diff(&left_p, &right_p);
    println!("{}", serde_json::to_string_pretty(&d)?);
    if !d.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

pub fn sign(path: &PathBuf) -> anyhow::Result<()> {
    let out = sign_policy_file(path)?;
    println!("OK  wrote {}", out.display());
    Ok(())
}
