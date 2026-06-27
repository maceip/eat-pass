//! On-the-wire bodies for the issuer HTTP API. The token/challenge/key formats
//! themselves live in `eat-pass-core` (RFC 9578/9577); this is only the
//! request/response envelope for the `/sign` gate.

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
