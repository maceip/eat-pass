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
use eat_pass_core::spend::{InMemorySpentStore, SpendError, SpentStore};
use eat_pass_core::{http, IssuerPublicKey, TokenChallenge, Verifier};

struct OriginState {
    verifier: Verifier,
    challenge: TokenChallenge,
    key_epoch: u32,
    spent: InMemorySpentStore,
    www_authenticate: String,
}

pub async fn run(
    listen: SocketAddr,
    issuer_url: String,
    issuer_name: String,
    origin_info: String,
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
    });

    eprintln!(
        "eat-pass origin: pinned issuer key v{key_epoch} token_key_id={}",
        hex::encode(tkid)
    );

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

    match state.spent.check_and_mark(state.key_epoch, &nonce) {
        Ok(()) => (
            StatusCode::OK,
            "access granted: valid attested, unlinkable, one-time token\n".to_string(),
        )
            .into_response(),
        Err(SpendError::DoubleSpend) => (
            StatusCode::CONFLICT,
            "token already spent (double-spend)\n".to_string(),
        )
            .into_response(),
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
