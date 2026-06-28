//! `eat-pass issuer` — blind-signing service (RSA key only).
//!
//! Issuance is gated on a short-lived [`IssuanceAuthorization`] from a
//! separate **attester** — this process never verifies raw EAT bytes.
//!
//! `GET /keys` publishes the issuer public key; `POST /sign` blind-signs only
//! when the client presents a valid attester-signed authorization bound to the
//! request's channel binding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::authorize::{attester_pubkey_from_hex, issue_authorized_with_limit, AttesterVerifyingKey};
use eat_pass_core::gate::GateError;
use eat_pass_core::transparency::{KeyLog, LogSigner, SignedHead};
use eat_pass_core::{Issuer, IssuerPublicKey, SignResponse};
use tokio::sync::RwLock;

use crate::store::LimitBackend;
use crate::tls::{serve, TlsPaths};
use crate::wire::{ErrorBody, KtResponse, RotateResponse, SignBody};

/// The mutable, rotation-aware part of the issuer: the current signing key, the
/// history of published public keys (so origins can verify older tokens), and
/// the transparency log + its current signed head.
struct Rotating {
    current: Issuer,
    history: HashMap<u32, IssuerPublicKey>,
    log: KeyLog,
    signed_head: SignedHead,
}

struct IssuerState {
    rot: RwLock<Rotating>,
    attester_pub: AttesterVerifyingKey,
    limiter: LimitBackend,
    log_signer: LogSigner,
    kt_log_pub: [u8; 32],
    admin_token: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: SocketAddr,
    attester_pub_hex: String,
    max_per_epoch: u32,
    epoch_secs: u64,
    rate_backend: Option<String>,
    tls: Option<TlsPaths>,
    insecure_http: bool,
) -> anyhow::Result<()> {
    let attester_pub = attester_pubkey_from_hex(&attester_pub_hex)
        .map_err(|e| anyhow::anyhow!("--attester-pub: {e}"))?;

    eprintln!("eat-pass issuer: generating PoMFRIT issuance key (key_version 1)…");
    let issuer = Issuer::generate(1);
    let pk = issuer.public();
    let tkid = pk.token_key_id()?;

    let limiter = LimitBackend::from_url(rate_backend.as_deref(), max_per_epoch, epoch_secs)?;
    let rate_label = limiter.label();

    let log_seed = kt_seed_from_env()?;
    let log_signer = LogSigner::from_seed(log_seed);
    let mut key_log = KeyLog::new();
    let now = unix_now();
    key_log
        .append(&pk, now)
        .map_err(|e| anyhow::anyhow!("kt append: {e}"))?;
    let kt_signed_head = log_signer.sign(&key_log);
    let kt_log_pub = log_signer.public();

    let admin_token = std::env::var("EATPASS_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());

    let mut history = HashMap::new();
    history.insert(pk.key_version, pk.clone());

    let state = Arc::new(IssuerState {
        rot: RwLock::new(Rotating {
            current: issuer,
            history,
            log: key_log,
            signed_head: kt_signed_head,
        }),
        attester_pub,
        limiter,
        log_signer,
        kt_log_pub,
        admin_token: admin_token.clone(),
    });

    eprintln!("  token_key_id   {}", hex::encode(tkid));
    eprintln!(
        "  attester pub   {} (authorization signatures)",
        attester_pub_hex.trim()
    );
    eprintln!("  rate limit     {max_per_epoch}/epoch ({epoch_secs}s) per attested build [{rate_label} backend]");
    eprintln!("  kt log pubkey  {}", hex::encode(kt_log_pub));
    eprintln!(
        "  rotation       {}",
        if admin_token.is_some() {
            "POST /rotate enabled (x-admin-token required)"
        } else {
            "POST /rotate disabled (set EATPASS_ADMIN_TOKEN to enable)"
        }
    );

    let app = Router::new()
        .route("/keys", get(keys))
        .route("/keys/:version", get(keys_version))
        .route("/kt", get(kt))
        .route("/sign", post(sign))
        .route("/rotate", post(rotate))
        .with_state(state);

    serve(app, listen, tls, insecure_http, "eat-pass issuer").await
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn kt_seed_from_env() -> anyhow::Result<[u8; 32]> {
    let h = std::env::var("EATPASS_KT_SEED").map_err(|_| {
        anyhow::anyhow!(
            "EATPASS_KT_SEED is required (64 hex chars): it is the stable \
             key-transparency log signing seed that clients pin. Generate one with \
             `openssl rand -hex 32` and persist it across restarts."
        )
    })?;
    let b = hex::decode(h.trim()).map_err(|e| anyhow::anyhow!("EATPASS_KT_SEED bad hex: {e}"))?;
    <[u8; 32]>::try_from(b.as_slice())
        .map_err(|_| anyhow::anyhow!("EATPASS_KT_SEED must be exactly 32 bytes (64 hex chars)"))
}

async fn keys(State(state): State<Arc<IssuerState>>) -> Json<IssuerPublicKey> {
    let g = state.rot.read().await;
    Json(g.current.public())
}

async fn keys_version(
    State(state): State<Arc<IssuerState>>,
    Path(version): Path<u32>,
) -> Result<Json<IssuerPublicKey>, (StatusCode, Json<ErrorBody>)> {
    let g = state.rot.read().await;
    g.history.get(&version).cloned().map(Json).ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            format!("no such key_version {version}"),
        )
    })
}

async fn kt(State(state): State<Arc<IssuerState>>) -> Json<KtResponse> {
    let g = state.rot.read().await;
    Json(KtResponse {
        log_pub: hex::encode(state.kt_log_pub),
        records: g.log.records().to_vec(),
        signed_head: g.signed_head.clone(),
    })
}

async fn sign(
    State(state): State<Arc<IssuerState>>,
    Json(body): Json<SignBody>,
) -> Result<Json<SignResponse>, (StatusCode, Json<ErrorBody>)> {
    let auth_bytes = B64.decode(body.authorization_b64.as_bytes()).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("authorization_b64 is not valid base64: {e}"),
        )
    })?;
    let auth: eat_pass_core::authorize::IssuanceAuthorization =
        serde_json::from_slice(&auth_bytes).map_err(|e| {
            err(
                StatusCode::BAD_REQUEST,
                format!("authorization JSON: {e}"),
            )
        })?;

    let g = state.rot.read().await;
    let now = unix_now();
    match issue_authorized_with_limit(
        &g.current,
        &state.attester_pub,
        &body.req,
        &auth,
        &state.limiter,
        now,
    ) {
        Ok(resp) => Ok(Json(resp)),
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

async fn rotate(
    State(state): State<Arc<IssuerState>>,
    headers: HeaderMap,
) -> Result<Json<RotateResponse>, (StatusCode, Json<ErrorBody>)> {
    let Some(expected) = state.admin_token.as_deref() else {
        return Err(err(
            StatusCode::NOT_FOUND,
            "rotation disabled (no admin token configured)".into(),
        ));
    };
    let presented = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if presented.is_empty() || presented != expected {
        return Err(err(
            StatusCode::FORBIDDEN,
            "bad or missing x-admin-token".into(),
        ));
    }

    let next_version = {
        let g = state.rot.read().await;
        g.current.public().key_version + 1
    };
    let new_issuer = Issuer::generate(next_version);
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("keygen: {e}")))?;
    let new_pk = new_issuer.public();
    let new_tkid = new_pk.token_key_id().map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("token_key_id: {e}"),
        )
    })?;
    let now = unix_now();

    let (seq, head_hex) = {
        let mut g = state.rot.write().await;
        let seq = g
            .log
            .append(&new_pk, now)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("kt append: {e}")))?;
        g.signed_head = state.log_signer.sign(&g.log);
        let head_hex = g.signed_head.head.clone();
        g.history.insert(new_pk.key_version, new_pk.clone());
        g.current = new_issuer;
        (seq, head_hex)
    };

    eprintln!(
        "issuer rotated → key_version {next_version} (kt seq {seq}, token_key_id {})",
        hex::encode(new_tkid)
    );
    Ok(Json(RotateResponse {
        key_version: next_version,
        token_key_id: hex::encode(new_tkid),
        kt_seq: seq,
        head: head_hex,
    }))
}

fn err(code: StatusCode, msg: String) -> (StatusCode, Json<ErrorBody>) {
    (code, Json(ErrorBody { error: msg }))
}

/// Attestation backend for the attester (shared with attester CLI).
pub enum Backend {
    Uq,
    Azure,
    AzureTls,
    AndroidKey,
    IosAppAttest,
    DesktopTpm,
    MacOsAppAttest,
}
