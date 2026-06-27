//! `eat-pass redeem` — a central double-spend authority (m2 shared-state).
//!
//! Origin-local spend tracking ([`eat_pass_core::spend::InMemorySpentStore`]) is
//! enough for a single origin, but a horizontally-scaled origin (many replicas
//! behind a load balancer) needs *shared* spend state — otherwise the same token
//! can be redeemed once per replica. This service is the simplest shared backend:
//! a single [`SpentStore`] reached over HTTP. Each origin replica forwards
//! `(key_epoch, nonce)` here instead of marking locally.
//!
//! It is intentionally backend-pluggable: the in-process store implements the
//! same [`SpentStore`] trait a Redis/DB-backed store would, so swapping the
//! storage layer does not change the wire contract.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use eat_pass_core::spend::{InMemorySpentStore, SpendError, SpentStore};

use crate::wire::{ErrorBody, RedeemBody};

struct RedeemState {
    spent: InMemorySpentStore,
}

pub async fn run(listen: SocketAddr) -> anyhow::Result<()> {
    let state = Arc::new(RedeemState {
        spent: InMemorySpentStore::new(),
    });
    let app = Router::new()
        .route("/redeem", post(redeem))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("eat-pass redeemer: listening on http://{listen}  (POST /redeem) — central double-spend authority");
    axum::serve(listener, app).await?;
    Ok(())
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
    }
}
