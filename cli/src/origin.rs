//! `eat-pass origin` — an example resource server gated on a token.
//!
//! `GET /resource` requires a valid RFC 9577 `Authorization: PrivateToken`. With
//! no token it answers `401` + `WWW-Authenticate: PrivateToken challenge=…,
//! token-key=…` (RFC 9577 §2.2) so a client knows exactly what to mint. A
//! presented token is verified against the issuer key + the challenge this
//! origin issues, then its nonce is spent once (origin-local double-spend
//! protection via [`eat_pass_core::spend`]).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use eat_pass_core::spend::{InMemorySpentStore, SpentStore};
use eat_pass_core::{http, IssuerPublicKey, TokenChallenge, Verifier};

use crate::wire::RedeemBody;

struct OriginState {
    verifier: Verifier,
    challenge: TokenChallenge,
    key_epoch: u32,
    spent: InMemorySpentStore,
    www_authenticate: String,
    /// When set, double-spend is enforced centrally (shared across replicas)
    /// via `POST {redeemer}/redeem`; otherwise it is origin-local.
    redeemer: Option<String>,
    http: reqwest::Client,
}

pub async fn run(
    listen: SocketAddr,
    issuer_url: String,
    issuer_name: String,
    origin_info: String,
    redeemer: Option<String>,
) -> anyhow::Result<()> {
    // Fetch + pin the issuer key this origin will accept tokens from.
    let keys_url = format!("{}/keys", issuer_url.trim_end_matches('/'));
    let pk: IssuerPublicKey = reqwest::Client::new()
        .get(&keys_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let key_epoch = pk.key_version;
    let tkid = pk.token_key_id()?;

    let challenge = TokenChallenge::new(issuer_name, origin_info);
    let www_authenticate = http::www_authenticate(&challenge.to_bytes(), &pk)
        .map_err(|e| anyhow::anyhow!("www-authenticate: {e}"))?;

    let state = Arc::new(OriginState {
        verifier: Verifier::new(pk),
        challenge,
        key_epoch,
        spent: InMemorySpentStore::new(),
        www_authenticate,
        redeemer: redeemer.map(|r| r.trim_end_matches('/').to_string()),
        http: reqwest::Client::new(),
    });

    eprintln!(
        "eat-pass origin: pinned issuer key v{key_epoch} token_key_id={}",
        hex::encode(tkid)
    );
    match &state.redeemer {
        Some(r) => eprintln!("eat-pass origin: double-spend via central redeemer {r}/redeem"),
        None => eprintln!("eat-pass origin: double-spend tracked origin-locally"),
    }

    let app = Router::new()
        .route("/resource", get(resource))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("eat-pass origin: listening on http://{listen}  (GET /resource)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn resource(State(state): State<Arc<OriginState>>, headers: HeaderMap) -> impl IntoResponse {
    let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return challenge_response(&state);
    };

    let token = match http::parse_authorization(auth) {
        Ok(t) => t,
        Err(_) => return challenge_response(&state),
    };

    let nonce = match state.verifier.verify(&token, &state.challenge) {
        Ok(n) => n,
        Err(e) => {
            return (StatusCode::FORBIDDEN, format!("token rejected: {e}\n")).into_response();
        }
    };

    let spent_ok = match &state.redeemer {
        Some(url) => spend_centrally(&state.http, url, state.key_epoch, &nonce).await,
        None => state.spent.check_and_mark(state.key_epoch, &nonce).is_ok(),
    };
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

fn challenge_response(state: &OriginState) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [("www-authenticate", state.www_authenticate.clone())],
        "PrivateToken required\n".to_string(),
    )
        .into_response()
}
