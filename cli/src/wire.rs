//! On-the-wire bodies for eat-pass HTTP APIs.

use eat_pass_core::authorize::IssuanceAuthorization;
use eat_pass_core::transparency::{KeyRecord, SignedHead};
use eat_pass_core::SignRequest;
use serde::{Deserialize, Serialize};

/// `POST /sign` body: blind-sign request plus attester-signed authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBody {
    pub req: SignRequest,
    /// Standard-base64 JSON [`IssuanceAuthorization`].
    pub authorization_b64: String,
}

/// `POST /authorize` body: raw attestation + channel binding to authorize.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeBody {
    pub eat_b64: String,
    /// 32-byte channel binding (64 hex chars) = `SignRequest.binding`.
    pub binding: String,
    pub max_batch: u32,
}

/// `POST /authorize` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    pub authorization_b64: String,
}

/// `GET /pubkey` on the attester.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PubkeyResponse {
    pub pubkey: String,
}

/// Error body returned when a gate rejects a request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// `GET /kt` body: the published key-transparency view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KtResponse {
    pub log_pub: String,
    pub records: Vec<KeyRecord>,
    pub signed_head: SignedHead,
}

/// `POST /rotate` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotateResponse {
    pub key_version: u32,
    pub token_key_id: String,
    pub kt_seq: u64,
    pub head: String,
}

/// `POST /redeem` body.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedeemBody {
    pub key_epoch: u32,
    pub nonce: String,
}

/// Re-export for wire roundtrips in tests.
pub type AuthorizationWire = IssuanceAuthorization;
