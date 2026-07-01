//! `eat-pass attester` — verifies hardware attestation and issues short-lived
//! [`IssuanceAuthorization`] tokens for the blind-signing issuer.
//!
//! The attester holds the attestation policy (measurement class) and a FAEST-128f
//! signing key. It never holds the PoMFRIT blind-signing key.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::authorize::{Authorizer, DEFAULT_AUTHORIZATION_TTL_SECS};
use eat_pass_core::gate::{AttestationVerifier, GateError, Measurement};
use eat_pass_gate::{
    AndroidKeyAttestationVerifier, AzureTlsVerifier, AzureUqVerifier, DesktopTpmVerifier,
    IosAppAttestVerifier, MacOsAppAttestVerifier, UqVerifier,
};
use eat_pass_policy::{
    load_for_attester, trusted_pubs_from_env, AppraisalResult, PolicyGated, VerificationPolicy,
};

use crate::issuer::Backend;
use crate::tls::{serve, TlsPaths};
use crate::wire::{AuthorizeBody, AuthorizeResponse, ErrorBody, PubkeyResponse};

pub enum Gate {
    Uq(PolicyGated<UqVerifier>),
    Azure(PolicyGated<AzureUqVerifier>),
    AzureTls(PolicyGated<AzureTlsVerifier>),
    AndroidKey(PolicyGated<AndroidKeyAttestationVerifier>),
    IosAppAttest(PolicyGated<IosAppAttestVerifier>),
    DesktopTpm(PolicyGated<DesktopTpmVerifier>),
    MacOsAppAttest(PolicyGated<MacOsAppAttestVerifier>),
}

impl Gate {
    fn verify_with_appraisal(
        &self,
        eat: &[u8],
        expected_binding: &[u8; 32],
    ) -> Result<(Measurement, AppraisalResult), GateError> {
        match self {
            Gate::Uq(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::Azure(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::AzureTls(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::AndroidKey(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::IosAppAttest(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::DesktopTpm(v) => v.verify_with_appraisal(eat, expected_binding),
            Gate::MacOsAppAttest(v) => v.verify_with_appraisal(eat, expected_binding),
        }
    }

    fn policy_label(&self) -> String {
        match self {
            Gate::Uq(v) => v.policy().measurement_class().policy_label(),
            Gate::Azure(v) => v.policy().measurement_class().policy_label(),
            Gate::AzureTls(v) => v.policy().measurement_class().policy_label(),
            Gate::AndroidKey(v) => v.policy().measurement_class().policy_label(),
            Gate::IosAppAttest(v) => v.policy().measurement_class().policy_label(),
            Gate::DesktopTpm(v) => v.policy().measurement_class().policy_label(),
            Gate::MacOsAppAttest(v) => v.policy().measurement_class().policy_label(),
        }
    }
}

impl AttestationVerifier for Gate {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        self.verify_with_appraisal(eat, expected_binding)
            .map(|(m, _)| m)
    }
}

struct AttesterState {
    authorizer: Authorizer<Gate>,
}

pub async fn run(
    listen: SocketAddr,
    backend: Backend,
    policy_path: PathBuf,
    gate_name: &str,
    auth_ttl_secs: u64,
    tls: Option<TlsPaths>,
    insecure_http: bool,
) -> anyhow::Result<()> {
    let trusted = trusted_pubs_from_env()?;
    let policy = load_for_attester(&policy_path, gate_name, &trusted)?;
    eprintln!(
        "  policy         id={} file={}",
        policy.id,
        policy_path.display()
    );
    if let Some(n) = &policy.notes {
        eprintln!("  policy notes   {n}");
    }
    if let Some(until) = policy.valid_until {
        eprintln!("  valid_until    {until}");
    }
    let class = policy.measurement_class();
    let policy_label = class.policy_label();

    let gate = match backend {
        Backend::Uq => {
            eprintln!("  gate           uq (unified-quote CBOR EAT verification)");
            Gate::Uq(PolicyGated::new(UqVerifier::new(), policy))
        }
        Backend::Azure => {
            eprintln!("  gate           azure (SEV-SNP vTPM bundle → AMD root)");
            Gate::Azure(PolicyGated::new(AzureUqVerifier::new(), policy))
        }
        Backend::AzureTls => {
            eprintln!("  gate           azure-tls (attested-TLS leaf cert → AMD root)");
            Gate::AzureTls(PolicyGated::new(AzureTlsVerifier::new(), policy))
        }
        Backend::AndroidKey => {
            eprintln!("  gate           android-key (KeyMint attestation, no Play Integrity)");
            Gate::AndroidKey(PolicyGated::new(
                AndroidKeyAttestationVerifier::new(),
                policy,
            ))
        }
        Backend::IosAppAttest => {
            eprintln!("  gate           ios-app-attest (App Attest assertion + binding)");
            Gate::IosAppAttest(PolicyGated::new(IosAppAttestVerifier::new(), policy))
        }
        Backend::DesktopTpm => {
            eprintln!(
                "  gate           desktop-tpm (Linux/Windows TPM2 AK quote + EK activation; require_ima={}, boot_allow={}, ek_roots={}, activation_keys={})",
                policy.require_ima,
                policy.boot_aggregates.len(),
                policy.desktop_tpm_ek_roots.len(),
                policy.desktop_tpm_activation_pubkeys.len()
            );
            let verifier = DesktopTpmVerifier::with_policy(
                policy.require_ima,
                policy.boot_aggregates_bytes(),
                policy.desktop_tpm_ek_roots_bytes(),
                policy.desktop_tpm_activation_pubkeys_bytes(),
            );
            Gate::DesktopTpm(PolicyGated::new(verifier, policy))
        }
        Backend::MacOsAppAttest => {
            eprintln!("  gate           macos-app-attest (App Attest assertion + binding)");
            Gate::MacOsAppAttest(PolicyGated::new(MacOsAppAttestVerifier::new(), policy))
        }
    };

    let seed = attester_seed_from_env()?;
    let authorizer = Authorizer::new(seed, gate, policy_label.clone(), auth_ttl_secs);
    let vk = authorizer.verifying_key();

    eprintln!(
        "eat-pass attester: ed25519 verifying key {}",
        hex::encode(vk)
    );
    eprintln!(
        "  measurement    class={policy_label} allow={}",
        class.len()
    );
    eprintln!("  auth ttl       {auth_ttl_secs}s (default {DEFAULT_AUTHORIZATION_TTL_SECS}s)");
    if !trusted.is_empty() {
        eprintln!(
            "  policy sig     verified ({} trusted key(s))",
            trusted.len()
        );
    }

    let state = Arc::new(AttesterState { authorizer });

    let app = Router::new()
        .route("/pubkey", get(pubkey))
        .route("/authorize", post(authorize))
        .route("/capability", post(authorize))
        .with_state(state);

    serve(app, listen, tls, insecure_http, "eat-pass attester").await
}

fn attester_seed_from_env() -> anyhow::Result<[u8; 32]> {
    let h = std::env::var("EATPASS_ATTESTER_SEED").map_err(|_| {
        anyhow::anyhow!(
            "EATPASS_ATTESTER_SEED is required (64 hex chars): stable ed25519 seed \
             for issuance-authorization signatures. Generate with `openssl rand -hex 32`."
        )
    })?;
    let b =
        hex::decode(h.trim()).map_err(|e| anyhow::anyhow!("EATPASS_ATTESTER_SEED bad hex: {e}"))?;
    <[u8; 32]>::try_from(b.as_slice()).map_err(|_| {
        anyhow::anyhow!("EATPASS_ATTESTER_SEED must be exactly 32 bytes (64 hex chars)")
    })
}

async fn pubkey(State(state): State<Arc<AttesterState>>) -> Json<PubkeyResponse> {
    Json(PubkeyResponse {
        pubkey: hex::encode(state.authorizer.verifying_key()),
    })
}

async fn authorize(
    State(state): State<Arc<AttesterState>>,
    Json(body): Json<AuthorizeBody>,
) -> Result<Json<AuthorizeResponse>, (StatusCode, Json<ErrorBody>)> {
    let eat = B64.decode(body.eat_b64.as_bytes()).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("eat_b64 is not valid base64: {e}"),
        )
    })?;
    let binding = parse_hex32(&body.binding, "binding")?;
    if body.max_batch == 0 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "max_batch must be non-zero".into(),
        ));
    }

    let now = unix_now();
    let gate = state.authorizer.verifier();
    let (measurement, appraisal) = gate
        .verify_with_appraisal(&eat, &binding)
        .map_err(|e| gate_err(e))?;
    let auth = state
        .authorizer
        .sign_authorization(&measurement, &binding, body.max_batch, now)
        .map_err(|e| gate_err(e))?;

    Ok(Json(AuthorizeResponse {
        authorization_b64: B64.encode(serde_json::to_vec(&auth).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encode authorization: {e}"),
            )
        })?),
        appraisal,
    }))
}

fn gate_err(e: GateError) -> (StatusCode, Json<ErrorBody>) {
    use GateError::*;
    let code = match e {
        QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    };
    err(code, e.to_string())
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], (StatusCode, Json<ErrorBody>)> {
    hex::decode(s.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                format!("{what} must be 32-byte hex (64 chars)"),
            )
        })
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn err(code: StatusCode, msg: String) -> (StatusCode, Json<ErrorBody>) {
    (code, Json(ErrorBody { error: msg }))
}
