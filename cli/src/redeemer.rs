//! `eat-pass redeem` — central double-spend authority.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use eat_pass_core::spend::{SpendError, SpentStore};

use crate::store::SpendBackend;
use crate::tls::{serve, TlsPaths};
use crate::wire::{ErrorBody, RedeemBody};

struct RedeemState {
    spent: SpendBackend,
}

pub async fn run(
    listen: SocketAddr,
    backend: Option<String>,
    ttl_secs: u64,
    tls: Option<TlsPaths>,
    insecure_http: bool,
) -> anyhow::Result<()> {
    let spent = SpendBackend::from_url(backend.as_deref(), ttl_secs)?;
    let _label = spent.label();
    let state = Arc::new(RedeemState { spent });
    let app = Router::new()
        .route("/redeem", post(redeem))
        .with_state(state);
    serve(
        app,
        listen,
        tls,
        insecure_http,
        "eat-pass redeemer",
    )
    .await
}

async fn redeem(
    State(state): State<Arc<RedeemState>>,
    Json(body): Json<RedeemBody>,
) -> Result<StatusCode, (StatusCode, Json<ErrorBody>)> {
    let nonce: [u8; 32] = hex::decode(body.nonce.trim())
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: "nonce must be 32-byte hex".into(),
                }),
            )
        })?;
    match state.spent.check_and_mark(body.key_epoch, &nonce) {
        Ok(()) => Ok(StatusCode::OK),
        Err(SpendError::DoubleSpend) => Err((
            StatusCode::CONFLICT,
            Json(ErrorBody {
                error: "token already spent (double-spend)".into(),
            }),
        )),
        Err(SpendError::Backend(e)) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorBody {
                error: format!("spend backend unavailable: {e}"),
            }),
        )),
    }
}
