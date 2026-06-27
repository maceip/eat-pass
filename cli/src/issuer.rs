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
use eat_pass_core::gate::{
    issue_gated_with_limit, AttestationVerifier, ClassGated, DevVerifier, GateError, Measurement,
    MeasurementClass,
};
use eat_pass_core::transparency::{KeyLog, KeyRecord, LogSigner, SignedHead};
use eat_pass_core::{Issuer, IssuerPublicKey, SignResponse};
use eat_pass_gate::{AzureTlsVerifier, AzureUqVerifier, UqVerifier};

use crate::store::LimitBackend;
use crate::wire::{ErrorBody, KtResponse, SignBody};

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

struct IssuerState {
    issuer: Issuer,
    verifier: Gate,
    limiter: LimitBackend,
    /// Published key-transparency view: the log records, the ed25519-signed
    /// head, and the log public key clients pin.
    kt_records: Vec<KeyRecord>,
    kt_signed_head: SignedHead,
    kt_log_pub: [u8; 32],
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
    // operator persists it and the log spans rotations.
    let log_seed = kt_seed_from_env();
    let log_signer = LogSigner::from_seed(log_seed);
    let mut key_log = KeyLog::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    key_log
        .append(&pk, now)
        .map_err(|e| anyhow::anyhow!("kt append: {e}"))?;
    let kt_signed_head = log_signer.sign(&key_log);
    let kt_log_pub = log_signer.public();

    let state = Arc::new(IssuerState {
        issuer,
        verifier,
        limiter,
        kt_records: key_log.records().to_vec(),
        kt_signed_head,
        kt_log_pub,
    });

    eprintln!("  token_key_id   {}", hex::encode(tkid));
    eprintln!(
        "  measurement    class={class_name}@v{class_version} accepted={}",
        allow.len()
    );
    eprintln!("  rate limit     {max_per_epoch}/epoch ({epoch_secs}s) per attested build [{rate_label} backend]");
    eprintln!("  kt log pubkey  {}", hex::encode(kt_log_pub));

    let app = Router::new()
        .route("/keys", get(keys))
        .route("/kt", get(kt))
        .route("/sign", post(sign))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("eat-pass issuer: listening on http://{listen}  (GET /keys, GET /kt, POST /sign)");
    axum::serve(listener, app).await?;
    Ok(())
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
    Json(state.issuer.public())
}

async fn kt(State(state): State<Arc<IssuerState>>) -> Json<KtResponse> {
    Json(KtResponse {
        log_pub: hex::encode(state.kt_log_pub),
        records: state.kt_records.clone(),
        signed_head: state.kt_signed_head.clone(),
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
