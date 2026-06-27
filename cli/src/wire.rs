//! On-the-wire bodies for the issuer HTTP API. The token/challenge/key formats
//! themselves live in `eat-pass-core` (RFC 9578/9577); this is only the
//! request/response envelope for the `/sign` gate.

use eat_pass_core::transparency::{KeyRecord, SignedHead};
use eat_pass_core::SignRequest;
use serde::{Deserialize, Serialize};

/// `POST /sign` body: the blind-signature request plus the attestation that
/// authorizes it. `eat_b64` is standard-base64 of the raw eat bytes (a
/// `DevEat` JSON today; a unified-quote EAT in m2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBody {
    pub req: SignRequest,
    pub eat_b64: String,
}

/// Error body returned by the issuer when the gate rejects a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// `GET /kt` body: the published key-transparency view. A client pins `log_pub`
/// out of band, verifies `records` reproduce `signed_head`, and confirms the
/// `/keys` token_key_id is included before trusting the issuer key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KtResponse {
    pub log_pub: String,
    pub records: Vec<KeyRecord>,
    pub signed_head: SignedHead,
}

/// `POST /rotate` response: the newly-installed signing key and where it landed
/// in the transparency log. After this, `GET /keys` serves `key_version` and the
/// log head advances to `kt_seq` — a client that pinned the log key sees the new
/// key as a *consistent append* to the chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateResponse {
    pub key_version: u32,
    pub token_key_id: String,
    pub kt_seq: u64,
    pub head: String,
}

/// `POST /redeem` body: a central double-spend authority shared by origin
/// replicas. `nonce` is hex of the token's 32-byte spend id; `key_epoch` is the
/// issuer key version that scopes it. The redeemer returns 200 the first time a
/// `(key_epoch, nonce)` is seen and 409 on any replay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemBody {
    pub key_epoch: u32,
    pub nonce: String,
}
