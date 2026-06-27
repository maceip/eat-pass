//! `eat-pass attester` — verifies hardware attestation and issues short-lived
//! [`IssuanceAuthorization`] tokens for the blind-signing issuer.
//!
//! The attester holds the attestation policy (measurement class) and an ed25519
//! signing key. It never holds the RSA blind-signing key.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::authorize::{Authorizer, DEFAULT_AUTHORIZATION_TTL_SECS};
use eat_pass_core::gate::{ClassGated, GateError, MeasurementClass};
use eat_pass_gate::{AzureTlsVerifier, AzureUqVerifier, UqVerifier};

use crate::issuer::Backend;
use crate::tls::{serve, TlsPaths};
use crate::wire::{AuthorizeBody, AuthorizeResponse, ErrorBody, PubkeyResponse};

pub enum Gate {
    Uq(ClassGated<UqVerifier>),
    Azure(ClassGated<AzureUqVerifier>),
    AzureTls(ClassGated<AzureTlsVerifier>),
}

impl eat_pass_core::gate::AttestationVerifier for Gate {
    fn verify(
        &self,
        eat: &[u8],
        expected_binding: &[u8; 32],
    ) -> Result<eat_pass_core::gate::Measurement, GateError> {
        match self {
            Gate::Uq(v) => v.verify(eat, expected_binding),
            Gate::Azure(v) => v.verify(eat, expected_binding),
            Gate::AzureTls(v) => v.verify(eat, expected_binding),
        }
    }
}

struct AttesterState {
    authorizer: Authorizer<Gate>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: SocketAddr,
    backend: Backend,
    allow: Vec<Vec<u8>>,
    class_name: String,
    class_version: u32,
    auth_ttl_secs: u64,
    tls: Option<TlsPaths>,
    insecure_http: bool,
) -> anyhow::Result<()> {
    let class = MeasurementClass::new(class_name.clone(), class_version, allow.clone());
    let policy_label = class.policy_label();
    let gate = match backend {
        Backend::Uq => {
            eprintln!("  gate           uq (unified-quote CBOR EAT verification)");
            Gate::Uq(ClassGated::new(UqVerifier::new(), class))
        }
        Backend::Azure => {
            eprintln!("  gate           azure (SEV-SNP vTPM bundle → AMD root)");
            Gate::Azure(ClassGated::new(AzureUqVerifier::new(), class))
        }
        Backend::AzureTls => {
            eprintln!("  gate           azure-tls (attested-TLS leaf cert → AMD root)");
            Gate::AzureTls(ClassGated::new(AzureTlsVerifier::new(), class))
        }
    };

    let seed = attester_seed_from_env()?;
    let authorizer = Authorizer::new(
        seed,
        gate,
        policy_label.clone(),
        auth_ttl_secs,
    );
    let vk = authorizer.verifying_key();

    eprintln!("eat-pass attester: ed25519 verifying key {}", hex::encode(vk));
    eprintln!(
        "  measurement    class={policy_label} accepted={}",
        allow.len()
    );
    eprintln!("  auth ttl       {auth_ttl_secs}s (default {DEFAULT_AUTHORIZATION_TTL_SECS}s)");

    let state = Arc::new(AttesterState { authorizer });

    let app = Router::new()
        .route("/pubkey", get(pubkey))
        .route("/authorize", post(authorize))
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
    let b = hex::decode(h.trim())
        .map_err(|e| anyhow::anyhow!("EATPASS_ATTESTER_SEED bad hex: {e}"))?;
    <[u8; 32]>::try_from(b.as_slice())
        .map_err(|_| anyhow::anyhow!("EATPASS_ATTESTER_SEED must be exactly 32 bytes (64 hex chars)"))
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
    match state
        .authorizer
        .authorize(&eat, &binding, body.max_batch, now)
    {
        Ok(auth) => Ok(Json(AuthorizeResponse {
            authorization_b64: B64.encode(serde_json::to_vec(&auth).map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("encode authorization: {e}"),
                )
            })?),
        })),
        Err(e) => {
            use GateError::*;
            let code = match e {
                QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::FORBIDDEN,
            };
            Err(err(code, e.to_string()))
        }
    }
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
