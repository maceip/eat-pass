//! `eat-pass issuer` — the issuance service.
//!
//! `GET /keys` publishes the current issuer public key (clients pin
//! `token_key_id = SHA256(SPKI)` from it); `GET /keys/{version}` serves a
//! historical key so an origin can verify a token minted under a now-rotated
//! key. `POST /sign` runs the attestation gate
//! ([`eat_pass_core::gate::issue_gated_with_limit`]) and blind-signs only if the
//! request carries a valid eat for an accepted measurement class, commits to the
//! request's channel binding, and is within the per-attestation epoch quota.
//!
//! `GET /kt` publishes the append-only, ed25519-signed key-transparency log.
//! `POST /rotate` (admin-gated) generates a new signing key, appends it to the
//! log, re-signs the head, and makes it current — so clients that pinned the
//! *log* key see the new key arrive as a consistent append (m3 key rotation).

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
use eat_pass_core::gate::{
    issue_gated_with_limit, AttestationVerifier, ClassGated, DevVerifier, GateError, Measurement,
    MeasurementClass,
};
use eat_pass_core::transparency::{KeyLog, LogSigner, SignedHead};
use eat_pass_core::{Issuer, IssuerPublicKey, SignResponse};
use eat_pass_gate::{AzureTlsVerifier, AzureUqVerifier, UqVerifier};
use tokio::sync::RwLock;

use crate::store::LimitBackend;
use crate::wire::{ErrorBody, KtResponse, RotateResponse, SignBody};

/// Which attestation backend gates issuance.
pub enum Gate {
    /// Dev ed25519 statements (`DevVerifier`) — no TEE needed, for local/CI.
    Dev(DevVerifier),
    /// Real unified-quote CBOR EAT verification (`UqVerifier`), class-gated.
    Uq(ClassGated<UqVerifier>),
    /// Azure SEV-SNP vTPM bundle (`value_x` = channel binding), class-gated.
    Azure(ClassGated<AzureUqVerifier>),
    /// Azure attested-TLS leaf cert (the live node's shape), class-gated.
    AzureTls(ClassGated<AzureTlsVerifier>),
}

impl AttestationVerifier for Gate {
    fn verify(&self, eat: &[u8], expected_binding: &[u8; 32]) -> Result<Measurement, GateError> {
        match self {
            Gate::Dev(v) => v.verify(eat, expected_binding),
            Gate::Uq(v) => v.verify(eat, expected_binding),
            Gate::Azure(v) => v.verify(eat, expected_binding),
            Gate::AzureTls(v) => v.verify(eat, expected_binding),
        }
    }
}

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
    verifier: Gate,
    limiter: LimitBackend,
    /// Long-lived log signing key; re-signs the head on every rotation.
    log_signer: LogSigner,
    /// The log public key clients pin (stable across rotations).
    kt_log_pub: [u8; 32],
    /// If set, `POST /rotate` requires header `x-admin-token` to match.
    admin_token: Option<String>,
    /// Modulus size used when minting a fresh key on rotation.
    modulus_bits: usize,
}

/// Issuance gate backend selected on the command line.
pub enum Backend {
    /// `--gate dev`: trust a dev attester verifying key (no TEE needed).
    Dev { attester_key: [u8; 32] },
    /// `--gate uq`: verify a real unified-quote CBOR EAT.
    Uq,
    /// `--gate azure`: verify an Azure SEV-SNP vTPM bundle (value_x bound).
    Azure,
    /// `--gate azure-tls`: verify an Azure attested-TLS leaf cert (DER).
    AzureTls,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: SocketAddr,
    backend: Backend,
    allow: Vec<Vec<u8>>,
    class_name: String,
    class_version: u32,
    modulus_bits: usize,
    max_per_epoch: u32,
    epoch_secs: u64,
    rate_backend: Option<String>,
) -> anyhow::Result<()> {
    eprintln!("eat-pass issuer: generating {modulus_bits}-bit issuance key (key_version 1)…");
    let issuer = Issuer::generate(1, modulus_bits)?;
    let pk = issuer.public();
    let tkid = pk.token_key_id()?;

    let class = MeasurementClass::new(class_name.clone(), class_version, allow.clone());
    let verifier = match backend {
        Backend::Dev { attester_key } => {
            let v = DevVerifier::new_for_class(attester_key, class)
                .map_err(|e| anyhow::anyhow!("verifier: {e}"))?;
            eprintln!(
                "  gate           dev (attester key {})",
                hex::encode(attester_key)
            );
            Gate::Dev(v)
        }
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

    // Rate-limit state is in-memory by default; a `redis://` URL makes it shared
    // across issuer replicas so the per-attestation quota is global, not
    // per-process (m3).
    let limiter = LimitBackend::from_url(rate_backend.as_deref(), max_per_epoch, epoch_secs)?;
    let rate_label = limiter.label();

    // Key transparency (E.4): publish this key in an append-only, signed log so
    // clients can pin the *log* key and refuse any issuer key not committed here.
    // The log seed is deterministic-from-env or random per process; in prod the
    // operator persists it so the log spans process restarts and rotations.
    let log_seed = kt_seed_from_env();
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
        verifier,
        limiter,
        log_signer,
        kt_log_pub,
        admin_token: admin_token.clone(),
        modulus_bits,
    });

    eprintln!("  token_key_id   {}", hex::encode(tkid));
    eprintln!(
        "  measurement    class={class_name}@v{class_version} accepted={}",
        allow.len()
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

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!(
        "eat-pass issuer: listening on http://{listen}  (GET /keys, /keys/:v, /kt, POST /sign, /rotate)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Key-log signing seed: hex in `EATPASS_KT_SEED` (64 chars), else random.
fn kt_seed_from_env() -> [u8; 32] {
    if let Ok(h) = std::env::var("EATPASS_KT_SEED") {
        if let Ok(b) = hex::decode(h.trim()) {
            if let Ok(arr) = <[u8; 32]>::try_from(b.as_slice()) {
                return arr;
            }
        }
        eprintln!("[issuer] WARNING: EATPASS_KT_SEED not 32-byte hex; using random log key");
    }
    let mut s = [0u8; 32];
    let _ = getrandom::getrandom(&mut s);
    s
}

async fn keys(State(state): State<Arc<IssuerState>>) -> Json<IssuerPublicKey> {
    let g = state.rot.read().await;
    Json(g.current.public())
}

/// Serve a historical (or current) issuer public key by version, so an origin
/// holding a token minted under a now-rotated key can fetch the key to verify
/// it. 404 if the version was never published by this issuer.
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
    let eat = B64.decode(body.eat_b64.as_bytes()).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            format!("eat_b64 is not valid base64: {e}"),
        )
    })?;

    let g = state.rot.read().await;
    match issue_gated_with_limit(&g.current, &state.verifier, &body.req, &eat, &state.limiter) {
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

/// Admin-gated key rotation: mint a fresh signing key, append it to the
/// transparency log, re-sign the head, and make it current. Tokens already
/// minted under the previous key keep verifying (origins fetch it via
/// `/keys/{version}`); spend sets are epoched by key_version so they stay
/// independent.
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
    // Constant-ish comparison is unnecessary here (the token is operator-held,
    // not user-supplied), but reject empties explicitly.
    if presented.is_empty() || presented != expected {
        return Err(err(
            StatusCode::FORBIDDEN,
            "bad or missing x-admin-token".into(),
        ));
    }

    // Determine the next version under a short read lock, then do the expensive
    // keygen OUTSIDE any lock so concurrent /sign and /keys keep serving.
    let next_version = {
        let g = state.rot.read().await;
        g.current.public().key_version + 1
    };
    let new_issuer = Issuer::generate(next_version, state.modulus_bits)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("keygen: {e}")))?;
    let new_pk = new_issuer.public();
    let new_tkid = new_pk.token_key_id().map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("token_key_id: {e}"),
        )
    })?;
    let now = unix_now();

    // Commit under the write lock: append, re-sign, install as current.
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
