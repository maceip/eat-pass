//! `eat-pass origin` — an example resource server gated on a token.
//!
//! `GET /resource` requires a valid RFC 9577 `Authorization: PrivateToken`. With
//! no token it answers `401` + `WWW-Authenticate: PrivateToken challenge=…,
//! token-key=…` (RFC 9577 §2.2) so a client knows exactly what to mint. A
//! presented token is verified against the issuer key + the challenge this
//! origin issued, then its nonce is spent once via the **central redeemer**
//! (`POST {redeemer}/redeem`) so double-spend is enforced globally across every
//! origin replica — there is no origin-local fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use eat_pass_core::transparency::verify_log;
use eat_pass_core::{http, IssuerPublicKey, TokenChallenge, Verifier};

use crate::tls::{serve, TlsPaths};
use crate::wire::{KtResponse, RedeemBody};

const MAX_RECENT_CHALLENGES: usize = 64;

/// A verifier for one issuer key version, plus the epoch its spends bucket into.
struct KeyEntry {
    verifier: Verifier,
    epoch: u32,
}

struct OriginState {
    /// Issuer base URL (no trailing slash) — used to resolve historical keys.
    base: String,
    issuer_name: String,
    origin_info: String,
    /// Current issuer key advertised in every fresh `WWW-Authenticate`.
    advertised_pk: IssuerPublicKey,
    /// Recently issued challenges (matched by `Token::challenge_digest` on redeem).
    recent_challenges: RwLock<Vec<TokenChallenge>>,
    /// When true, every challenge carries a fresh 32-byte redemption context.
    require_redemption_context: bool,
    /// `token_key_id -> KeyEntry`, seeded with the current key and filled in
    /// lazily as tokens from older (rotated-out) key versions arrive. This is
    /// what closes the rotation gap: a token minted under v1 is still accepted
    /// after the issuer rotates to v2, instead of being rejected because the
    /// origin pinned exactly one key at startup.
    keys: RwLock<HashMap<[u8; 32], Arc<KeyEntry>>>,
    /// A key is only ever trusted if it is included in the issuer's
    /// transparency log and that log verifies under this pinned ed25519 key.
    kt_log_pub: [u8; 32],
    /// Double-spend is always enforced centrally (shared across replicas) via
    /// `POST {redeemer}/redeem`. There is no origin-local fallback.
    redeemer: String,
    http: reqwest::Client,
}

pub async fn run(
    listen: SocketAddr,
    issuer_url: String,
    issuer_name: String,
    origin_info: String,
    redeemer: String,
    kt_log_pub: [u8; 32],
    tls: Option<TlsPaths>,
    insecure_http: bool,
    insecure_tls: bool,
    require_redemption_context: bool,
) -> anyhow::Result<()> {
    let base = issuer_url.trim_end_matches('/').to_string();
    let mut http_builder = reqwest::Client::builder();
    if insecure_tls {
        http_builder = http_builder.danger_accept_invalid_certs(true);
    }
    let http = http_builder.build()?;

    // Fetch the *current* issuer key — this is the one we advertise to new
    // clients via WWW-Authenticate. Older versions are resolved on demand.
    let pk: IssuerPublicKey = http
        .get(format!("{base}/keys"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let cur_epoch = pk.key_version;
    let cur_tkid = pk.token_key_id()?;

    let mut keys = HashMap::new();
    keys.insert(
        cur_tkid,
        Arc::new(KeyEntry {
            verifier: Verifier::new(pk.clone()),
            epoch: cur_epoch,
        }),
    );

    let state = Arc::new(OriginState {
        base,
        issuer_name,
        origin_info,
        advertised_pk: pk,
        recent_challenges: RwLock::new(Vec::new()),
        require_redemption_context,
        keys: RwLock::new(keys),
        kt_log_pub,
        redeemer: redeemer.trim_end_matches('/').to_string(),
        http,
    });

    eprintln!(
        "eat-pass origin: advertising current issuer key v{cur_epoch} token_key_id={}",
        hex::encode(cur_tkid)
    );
    eprintln!(
        "eat-pass origin: accepting only keys included in the transparency log signed by {}",
        hex::encode(state.kt_log_pub)
    );
    eprintln!(
        "eat-pass origin: double-spend enforced via central redeemer {}/redeem",
        state.redeemer
    );
    if require_redemption_context {
        eprintln!("eat-pass origin: each 401 issues a fresh 32-byte redemption context");
    }

    let app = Router::new()
        .route("/resource", get(resource))
        .with_state(state);

    serve(app, listen, tls, insecure_http, "eat-pass origin").await
}

fn issue_fresh_challenge(state: &OriginState) -> anyhow::Result<(TokenChallenge, String)> {
    let mut ch = TokenChallenge::new(&state.issuer_name, &state.origin_info);
    if state.require_redemption_context {
        ch = ch
            .with_random_redemption_context()
            .map_err(|e| anyhow::anyhow!("redemption context: {e}"))?;
    }
    {
        let mut recent = state.recent_challenges.write().unwrap();
        recent.push(ch.clone());
        if recent.len() > MAX_RECENT_CHALLENGES {
            let drop = recent.len() - MAX_RECENT_CHALLENGES;
            recent.drain(0..drop);
        }
    }
    let www = http::www_authenticate(&ch.to_bytes(), &state.advertised_pk)
        .map_err(|e| anyhow::anyhow!("www-authenticate: {e}"))?;
    Ok((ch, www))
}

fn challenge_for_digest(state: &OriginState, digest: &[u8; 32]) -> Option<TokenChallenge> {
    state
        .recent_challenges
        .read()
        .unwrap()
        .iter()
        .find(|c| c.digest() == *digest)
        .cloned()
}

/// Return the [`KeyEntry`] for a token's `token_key_id`, resolving and caching
/// it from the issuer's transparency log + `/keys/{version}` on a cache miss.
/// `None` means the key is genuinely not one this origin will accept (absent
/// from the log, or fails the pinned-log check).
async fn key_for(state: &Arc<OriginState>, tkid: &[u8; 32]) -> Option<Arc<KeyEntry>> {
    if let Some(e) = state.keys.read().unwrap().get(tkid).cloned() {
        return Some(e);
    }
    match resolve_via_kt(state, tkid).await {
        Ok(Some(entry)) => {
            state.keys.write().unwrap().insert(*tkid, entry.clone());
            Some(entry)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!(
                "eat-pass origin: could not resolve key {}: {e}",
                hex::encode(tkid)
            );
            None
        }
    }
}

/// Map an unknown `token_key_id` to its key version via the issuer's `/kt` log
/// (optionally verifying the log under a pinned key), then fetch and validate
/// that key from `/keys/{version}`.
async fn resolve_via_kt(
    state: &Arc<OriginState>,
    tkid: &[u8; 32],
) -> anyhow::Result<Option<Arc<KeyEntry>>> {
    let kt: KtResponse = state
        .http
        .get(format!("{}/kt", state.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let pin = state.kt_log_pub;
    let served = hex::decode(kt.log_pub.trim()).unwrap_or_default();
    if served.as_slice() != pin {
        anyhow::bail!(
            "kt log pubkey {} does not match the pinned key {}",
            kt.log_pub,
            hex::encode(pin)
        );
    }
    verify_log(&pin, &kt.records, &kt.signed_head)
        .map_err(|e| anyhow::anyhow!("kt log does not verify under pinned key: {e}"))?;

    let want = hex::encode(tkid);
    let Some(rec) = kt
        .records
        .iter()
        .find(|r| r.token_key_id.eq_ignore_ascii_case(&want))
    else {
        return Ok(None);
    };
    let version = rec.key_version;

    let pk: IssuerPublicKey = state
        .http
        .get(format!("{}/keys/{version}", state.base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let epoch = pk.key_version;
    if pk.token_key_id()? != *tkid {
        anyhow::bail!("/keys/{version} token_key_id disagrees with the transparency log");
    }
    eprintln!("eat-pass origin: resolved rotated-out key v{epoch} token_key_id={want}");
    Ok(Some(Arc::new(KeyEntry {
        verifier: Verifier::new(pk),
        epoch,
    })))
}

async fn resource(State(state): State<Arc<OriginState>>, headers: HeaderMap) -> impl IntoResponse {
    let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return challenge_response(&state).await;
    };

    let token = match http::parse_authorization(auth) {
        Ok(t) => t,
        Err(_) => return challenge_response(&state).await,
    };

    // Resolve the key this token was signed under (current or a rotated-out
    // version), so rotation never invalidates already-minted tokens.
    let Some(entry) = key_for(&state, &token.token_key_id).await else {
        return (
            StatusCode::FORBIDDEN,
            "token signed by an unknown or unaccepted issuer key\n".to_string(),
        )
            .into_response();
    };

    let Some(challenge) = challenge_for_digest(&state, &token.challenge_digest) else {
        return (
            StatusCode::FORBIDDEN,
            "token challenge unknown or expired (mint against a fresh WWW-Authenticate)\n"
                .to_string(),
        )
            .into_response();
    };

    if state.require_redemption_context && !challenge.has_redemption_context() {
        return (
            StatusCode::FORBIDDEN,
            "origin requires a 32-byte redemption context on the challenge\n".to_string(),
        )
            .into_response();
    }

    let nonce = match entry.verifier.verify(&token, &challenge) {
        Ok(n) => n,
        Err(e) => {
            return (StatusCode::FORBIDDEN, format!("token rejected: {e}\n")).into_response();
        }
    };

    let spent_ok = spend_centrally(&state.http, &state.redeemer, entry.epoch, &nonce).await;
    if spent_ok {
        (
            StatusCode::OK,
            "access granted: valid attested, unlinkable, one-time token\n".to_string(),
        )
            .into_response()
    } else {
        (
            StatusCode::CONFLICT,
            "token already spent (double-spend)\n".to_string(),
        )
            .into_response()
    }
}

/// Forward the spend to the central redeemer. Returns `true` if this is the
/// first time the nonce was seen (HTTP 200), `false` on a double-spend (409) or
/// any redeemer error (fail-closed — we do not grant access we can't account
/// for).
async fn spend_centrally(
    http: &reqwest::Client,
    url: &str,
    key_epoch: u32,
    nonce: &[u8; 32],
) -> bool {
    let body = RedeemBody {
        key_epoch,
        nonce: hex::encode(nonce),
    };
    match http.post(format!("{url}/redeem")).json(&body).send().await {
        Ok(r) => r.status() == StatusCode::OK,
        Err(_) => false,
    }
}

async fn challenge_response(state: &Arc<OriginState>) -> axum::response::Response {
    match issue_fresh_challenge(state) {
        Ok((_ch, www)) => (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", www)],
            "PrivateToken required\n".to_string(),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("could not issue challenge: {e}\n"),
        )
            .into_response(),
    }
}
