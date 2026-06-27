//! `eat-pass issuer` — the issuance service.
//!
//! `GET /keys` publishes the issuer public key (clients pin `token_key_id =
//! SHA256(SPKI)` from it). `POST /sign` runs the attestation gate
//! ([`eat_pass_core::gate::issue_gated_with_limit`]) and blind-signs only if the
//! request carries a valid eat for an accepted measurement class, commits to the
//! request's channel binding, and is within the per-attestation epoch quota.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::gate::{issue_gated_with_limit, DevVerifier, MeasurementClass};
use eat_pass_core::ratelimit::InMemoryRateLimiter;
use eat_pass_core::{Issuer, IssuerPublicKey, SignResponse};

use crate::wire::{ErrorBody, SignBody};

struct IssuerState {
    issuer: Issuer,
    verifier: DevVerifier,
    limiter: InMemoryRateLimiter,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: SocketAddr,
    attester_key: [u8; 32],
    allow: Vec<Vec<u8>>,
    class_name: String,
    class_version: u32,
    modulus_bits: usize,
    max_per_epoch: u32,
    epoch_secs: u64,
) -> anyhow::Result<()> {
    eprintln!("eat-pass issuer: generating {modulus_bits}-bit issuance key (key_version 1)…");
    let issuer = Issuer::generate(1, modulus_bits)?;
    let pk = issuer.public();
    let tkid = pk.token_key_id()?;

    let class = MeasurementClass::new(class_name.clone(), class_version, allow.clone());
    let verifier = DevVerifier::new_for_class(attester_key, class)
        .map_err(|e| anyhow::anyhow!("verifier: {e}"))?;
    let limiter = InMemoryRateLimiter::new(max_per_epoch, epoch_secs);

    let state = Arc::new(IssuerState {
        issuer,
        verifier,
        limiter,
    });

    eprintln!("  token_key_id   {}", hex::encode(tkid));
    eprintln!(
        "  measurement    class={class_name}@v{class_version} accepted={}",
        allow.len()
    );
    eprintln!("  rate limit     {max_per_epoch}/epoch ({epoch_secs}s) per attested build");
    eprintln!("  attester key   {}", hex::encode(attester_key));

    let app = Router::new()
        .route("/keys", get(keys))
        .route("/sign", post(sign))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("eat-pass issuer: listening on http://{listen}  (GET /keys, POST /sign)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn keys(State(state): State<Arc<IssuerState>>) -> Json<IssuerPublicKey> {
    Json(state.issuer.public())
}

async fn sign(
    State(state): State<Arc<IssuerState>>,
    Json(body): Json<SignBody>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorBody>)> {
    let eat = B64.decode(body.eat_b64.as_bytes()).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("eat_b64 is not valid base64: {e}"),
        )
    })?;

    match issue_gated_with_limit(
        &state.issuer,
        &state.verifier,
        &body.req,
        &eat,
        &state.limiter,
    ) {
        Ok(resp) => Ok(Json(resp)),
        Err(e) => {
            use eat_pass_core::gate::GateError::*;
            // Quota is a 429; everything else the client got wrong/forged is a 403.
            let code = match e {
                QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
                _ => StatusCode::FORBIDDEN,
            };
            Err(err(code, e.to_string()))
        }
    }
}

fn err(code: StatusCode, msg: String) -> (StatusCode, Json<ErrorBody>) {
    (code, Json(ErrorBody { error: msg }))
}
