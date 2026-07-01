//! `eat-pass-mobile` — the eat-pass **client** crypto, exposed to Android
//! (Kotlin) and iOS (Swift) through [UniFFI](https://mozilla.github.io/uniffi-rs/).
//!
//! Mobile is a client: it blinds token inputs, gets them blind-signed by an
//! issuer, and finalizes them into unlinkable [`Token`]s it later presents to an
//! origin. The two halves that touch the network and the secure element —
//! HTTP and *attestation* — are intentionally **left to the host app**, because
//! on mobile the attestation evidence comes from a platform API (Android
//! KeyMint / Play Integrity, iOS App Attest) rather than a unified-quote TEE.
//! This crate therefore exposes only the unlinkable-credential math:
//!
//! ```text
//! Kotlin/Swift                         Rust (this crate)            issuer
//! ────────────                         ─────────────────            ──────
//! new(issuer_pk_json, names) ───────▶  EatPassClient
//! begin(count)             ───────────▶ blind N inputs ──▶ {req_json, binding}
//!   (host attests over `binding`, POSTs req_json + eat to /sign) ───────────▶
//!   (host receives sign_response_json) ◀───────────────────────────────────
//! finalize(sign_response_json) ──────▶ unblind ──▶ ["PrivateToken token=…", …]
//! ```
//!
//! The returned strings are ready-to-send RFC 9577 `Authorization` header
//! values. Blinding secrets never cross the FFI boundary (they live inside the
//! [`EatPassClient`] object), preserving unlinkability.

use std::sync::Mutex;

use eat_pass_core::{http, Client, IssuerPublicKey, PendingTokens, SignResponse, TokenChallenge};

uniffi::setup_scaffolding!();

/// Errors surfaced to Kotlin/Swift. Flattened to a message so the host gets a
/// stable, displayable string regardless of the underlying core error.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MobileError {
    #[error("invalid issuer public key json: {0}")]
    BadIssuerKey(String),
    #[error("invalid sign response json: {0}")]
    BadSignResponse(String),
    #[error("begin() must be called before finalize()")]
    NoPendingRequest,
    #[error("eat-pass core error: {0}")]
    Core(String),
}

/// The result of [`EatPassClient::begin`]: the JSON `/sign` request body the
/// host POSTs to the issuer, and the hex channel binding the host's attestation
/// must commit to (`eat_nonce`/`value_x`), tying the quote to *this* request.
#[derive(uniffi::Record)]
pub struct BeginResult {
    /// JSON of the `SignRequest` (send as the `req` field of the `/sign` body).
    pub request_json: String,
    /// Hex of the 32-byte channel binding the attestation must bind.
    pub binding_hex: String,
}

/// A stateful eat-pass client bound to one issuer key + one origin challenge.
/// Hold one per (issuer, origin) pair; `begin`/`finalize` form one issuance.
#[derive(uniffi::Object)]
pub struct EatPassClient {
    pk: IssuerPublicKey,
    challenge: TokenChallenge,
    pending: Mutex<Option<PendingTokens>>,
}

#[uniffi::export]
impl EatPassClient {
    /// Construct from the issuer's published `/keys` JSON and the challenge
    /// identifiers (`issuer_name`, `origin_info`) that must match the origin.
    #[uniffi::constructor]
    pub fn new(
        issuer_pk_json: String,
        issuer_name: String,
        origin_info: String,
    ) -> Result<std::sync::Arc<Self>, MobileError> {
        let pk: IssuerPublicKey = serde_json::from_str(&issuer_pk_json)
            .map_err(|e| MobileError::BadIssuerKey(e.to_string()))?;
        Ok(std::sync::Arc::new(Self {
            pk,
            challenge: TokenChallenge::new(issuer_name, origin_info),
            pending: Mutex::new(None),
        }))
    }

    /// The `token_key_id` (hex of SHA256(SPKI)) the host should pin / verify in a
    /// key-transparency log before issuance.
    pub fn token_key_id_hex(&self) -> Result<String, MobileError> {
        self.pk
            .token_key_id()
            .map(hex::encode)
            .map_err(|e| MobileError::Core(e.to_string()))
    }

    /// Blind `count` token inputs. Returns the `/sign` request JSON and the
    /// channel binding the host must attest over. Overwrites any prior pending
    /// batch on this client.
    pub fn begin(&self, count: u32) -> Result<BeginResult, MobileError> {
        let (req, pending) = Client::begin(&self.pk, &self.challenge, count as usize)
            .map_err(|e| MobileError::Core(e.to_string()))?;
        let request_json =
            serde_json::to_string(&req).map_err(|e| MobileError::Core(e.to_string()))?;
        let binding_hex = hex::encode(req.binding());
        *self.pending.lock().expect("pending mutex") = Some(pending);
        Ok(BeginResult {
            request_json,
            binding_hex,
        })
    }

    /// Finalize the issuer's `/sign` response (JSON) into ready-to-send
    /// `Authorization: PrivateToken token=…` header values. Consumes the pending
    /// batch from the matching [`begin`](Self::begin).
    pub fn finalize(&self, sign_response_json: String) -> Result<Vec<String>, MobileError> {
        let resp: SignResponse = serde_json::from_str(&sign_response_json)
            .map_err(|e| MobileError::BadSignResponse(e.to_string()))?;
        let pending = self
            .pending
            .lock()
            .expect("pending mutex")
            .take()
            .ok_or(MobileError::NoPendingRequest)?;
        let tokens = pending
            .finalize(&self.pk, &resp)
            .map_err(|e| MobileError::Core(e.to_string()))?;
        Ok(tokens.iter().map(http::authorization).collect())
    }
}

/// Domain-separated build identity for desktop TPM policy (`allow[].measurement`).
#[uniffi::export]
pub fn desktop_build_id_hash_hex(build_digest_hex: String) -> Result<String, MobileError> {
    let digest = parse_hex32(&build_digest_hex, "build_digest")?;
    Ok(hex::encode(
        unified_quote::tee::desktop::desktop_build_id_hash(&digest),
    ))
}

/// `clientDataHash` for macOS/iOS App Attest before `generateAssertion`.
#[uniffi::export]
pub fn ios_client_data_hash_hex(binding_hex: String) -> Result<String, MobileError> {
    let binding = parse_hex32(&binding_hex, "binding")?;
    Ok(hex::encode(
        unified_quote::tee::mobile::ios_client_data_hash(&binding),
    ))
}

fn parse_hex32(hex_str: &str, field: &str) -> Result<[u8; 32], MobileError> {
    let v = hex::decode(hex_str.trim()).map_err(|e| MobileError::Core(format!("{field}: {e}")))?;
    v.as_slice()
        .try_into()
        .map_err(|_| MobileError::Core(format!("{field} must be 32 bytes (64 hex chars)")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use eat_pass_core::gate::{issue_gated, DevAttester, DevVerifier, Measurement};
    use eat_pass_core::Issuer;

    // Exercises the exact FFI surface a phone would call: new → begin →
    // (attest + sign, done here in-process) → finalize → header strings.
    #[test]
    fn ffi_surface_mints_presentable_tokens() {
        let issuer = Issuer::generate(1);
        let pk_json = serde_json::to_string(&issuer.public()).unwrap();

        let attester = DevAttester::from_seed([3u8; 32]);
        let value_x = vec![0xCD; 48];
        let verifier = DevVerifier::new(attester.verifying_key(), vec![value_x.clone()]).unwrap();

        let client =
            EatPassClient::new(pk_json, "issuer.example".into(), "origin.example".into()).unwrap();

        let begin = client.begin(2).unwrap();
        // Host attests over the binding the FFI handed back.
        let binding: [u8; 32] = hex::decode(&begin.binding_hex).unwrap().try_into().unwrap();
        let measurement = Measurement::new("dev", value_x);
        let eat = attester.attest(&measurement, &binding);
        let req = serde_json::from_str(&begin.request_json).unwrap();
        let resp = issue_gated(&issuer, &verifier, &req, &eat).unwrap();

        let headers = client
            .finalize(serde_json::to_string(&resp).unwrap())
            .unwrap();
        assert_eq!(headers.len(), 2);
        for h in &headers {
            assert!(h.starts_with("PrivateToken token="));
            // And it parses back to a token the origin could verify.
            http::parse_authorization(h).expect("header parses");
        }

        // finalize again with no pending batch is a clean error, not a panic.
        let err = client.finalize("{}".into()).unwrap_err();
        assert!(matches!(
            err,
            MobileError::NoPendingRequest | MobileError::BadSignResponse(_)
        ));
    }
}
