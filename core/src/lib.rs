//! eat-pass-core — attestation-gated, unlinkable authorization tokens.
//!
//! The credential is an RSA blind signature (RFC 9474, RSABSSA-SHA384-PSS-
//! **Deterministic**) over a Privacy Pass token input (RFC 9578 token type
//! `0x0002`). An issuer blind-signs the token input without seeing the nonce,
//! so a finalized token cannot be linked to its issuance. Issuance is meant to
//! be *gated* on attestation: see [`gate`].
//!
//! Roles:
//! - [`Client`] blinds token inputs and finalizes tokens.
//! - [`Issuer`] holds the keypair and blind-signs (crypto only; the gate lives
//!   in [`gate`]).
//! - [`Verifier`] (an origin) checks a token with nothing but the public key,
//!   the [`TokenChallenge`] it issued, and the pinned `token_key_id`.
//!
//! ## Interop
//!
//! - **RFC 9578** — the wire token is `Token{token_type, nonce,
//!   challenge_digest, token_key_id, authenticator}`; [`Token::to_bytes`] /
//!   [`Token::from_bytes`] are the byte form.
//! - **RFC 9577** — [`http`] builds `WWW-Authenticate: PrivateToken …` and
//!   parses `Authorization: PrivateToken token=…`.
//! - **Deterministic** issuance (no per-message randomizer) matches the Privacy
//!   Access Token (PAT) profile so any RFC-9578 origin can verify our tokens.

pub mod gate;
pub mod pbrsa;
pub mod ratelimit;
mod serdehelp;
pub mod spend;
pub mod transparency;

use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng,
    KeyPairSha384PSSDeterministic as KeyPair, PublicKeySha384PSSDeterministic as RsaPublicKey,
    SecretKeySha384PSSDeterministic as RsaSecretKey, Signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// RFC 9474 profile we issue under. Deterministic (no message randomizer) for
/// RFC 9578 token-type-0x0002 interop.
pub const ALG: &str = "RSABSSA-SHA384-PSS-Deterministic";
/// Default issuer modulus size.
pub const DEFAULT_MODULUS_BITS: usize = 3072;
/// RFC 9578 token type for publicly-verifiable blind-RSA tokens.
pub const TOKEN_TYPE_BLIND_RSA: u16 = 0x0002;

const BINDING_DOMAIN: &[u8] = b"eat-pass/v0/binding\0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("blind-rsa: {0}")]
    Brs(String),
    #[error("rng: {0}")]
    Rng(String),
    #[error("issuer returned {got} signatures for {want} requests")]
    CountMismatch { want: usize, got: usize },
    #[error("key version mismatch: token wants v{want}, have v{have}")]
    KeyVersion { want: u32, have: u32 },
    #[error("token_key_id mismatch: token bound to a different issuer key")]
    KeyIdMismatch,
    #[error("challenge mismatch: token was issued for a different challenge")]
    ChallengeMismatch,
    #[error("token type {got} unsupported (want {want})")]
    TokenType { want: u16, got: u16 },
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<blind_rsa_signatures::Error> for Error {
    fn from(e: blind_rsa_signatures::Error) -> Self {
        Error::Brs(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// TokenChallenge (RFC 9577 §2.1) — replaces the coarse UseCase separator (E.2)
// ---------------------------------------------------------------------------

/// A Privacy Pass token challenge. Binds a token to an issuer, an origin, and
/// an optional redemption context (which doubles as a freshness nonce: an
/// origin that rotates `redemption_context` per request kills EAT/token replay
/// inside the validity window — the L1.1 tie-in).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenChallenge {
    pub token_type: u16,
    pub issuer_name: String,
    /// 0 or 32 bytes (RFC 9577). Empty = "no redemption context".
    #[serde(with = "serdehelp::b64vec")]
    pub redemption_context: Vec<u8>,
    pub origin_info: String,
}

impl TokenChallenge {
    /// A challenge with no redemption context, for a single origin.
    pub fn new(issuer_name: impl Into<String>, origin_info: impl Into<String>) -> Self {
        Self {
            token_type: TOKEN_TYPE_BLIND_RSA,
            issuer_name: issuer_name.into(),
            redemption_context: Vec::new(),
            origin_info: origin_info.into(),
        }
    }

    /// Attach a 32-byte redemption context (per-request freshness nonce).
    pub fn with_redemption_context(mut self, ctx: [u8; 32]) -> Self {
        self.redemption_context = ctx.to_vec();
        self
    }

    /// RFC 9577 presentation encoding (length-prefixed fields).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.token_type.to_be_bytes());
        let iss = self.issuer_name.as_bytes();
        v.extend_from_slice(&(iss.len() as u16).to_be_bytes());
        v.extend_from_slice(iss);
        v.push(self.redemption_context.len() as u8);
        v.extend_from_slice(&self.redemption_context);
        let org = self.origin_info.as_bytes();
        v.extend_from_slice(&(org.len() as u16).to_be_bytes());
        v.extend_from_slice(org);
        v
    }

    /// `challenge_digest = SHA256(TokenChallenge)` (RFC 9578 §2.2).
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }
}

/// RFC 9578 token_input: the bytes the issuer blind-signs.
/// `token_type ‖ nonce ‖ challenge_digest ‖ token_key_id`.
pub(crate) fn token_input(
    nonce: &[u8; 32],
    challenge_digest: &[u8; 32],
    token_key_id: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 32 + 32 + 32);
    v.extend_from_slice(&TOKEN_TYPE_BLIND_RSA.to_be_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(challenge_digest);
    v.extend_from_slice(token_key_id);
    v
}

/// Channel binding: a stable hash over the blinded messages in a request. The
/// attestation gate requires the eat to commit to exactly this value, so a
/// captured eat cannot be replayed against a different blind request.
pub fn binding_of(blinded: &[BlindMessage]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BINDING_DOMAIN);
    h.update((blinded.len() as u32).to_be_bytes());
    for b in blinded {
        let bytes: &[u8] = b.as_ref();
        h.update((bytes.len() as u32).to_be_bytes());
        h.update(bytes);
    }
    h.finalize().into()
}

pub(crate) fn random_nonce() -> Result<[u8; 32], Error> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(n)
}

/// `token_key_id = SHA256(SPKI)` (RFC 9578 §8.2.2). Pinning this in the token
/// and checking it on redemption defeats split-view key attacks (E.4).
pub fn token_key_id(pk: &RsaPublicKey) -> Result<[u8; 32], Error> {
    let spki = pk.to_spki().map_err(Error::from)?;
    Ok(Sha256::digest(&spki).into())
}

/// The issuer's public key, as published at `/keys`.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    pub key_version: u32,
    pub alg: String,
    pub key: RsaPublicKey,
}

impl IssuerPublicKey {
    /// `token_key_id` for this key — pinned into every token (E.4).
    pub fn token_key_id(&self) -> Result<[u8; 32], Error> {
        token_key_id(&self.key)
    }
}

/// Key-consistency check (E.4): confirm a served issuer key matches a
/// `token_key_id` pinned out-of-band (e.g. from a transparency log or a prior
/// observation). A split-view issuer that serves different keys to different
/// clients to deanonymize them fails this.
pub fn check_key_consistency(pinned: &[u8; 32], pk: &IssuerPublicKey) -> Result<(), Error> {
    if &pk.token_key_id()? == pinned {
        Ok(())
    } else {
        Err(Error::KeyIdMismatch)
    }
}

/// The issuer: holds the keypair, blind-signs requests. The eligibility gate is
/// applied separately (see [`gate`]) — this type performs crypto only.
pub struct Issuer {
    sk: RsaSecretKey,
    pk: RsaPublicKey,
    key_version: u32,
}

impl Issuer {
    pub fn generate(key_version: u32, modulus_bits: usize) -> Result<Self, Error> {
        let kp = KeyPair::generate(&mut DefaultRng, modulus_bits)?;
        Ok(Self {
            sk: kp.sk,
            pk: kp.pk,
            key_version,
        })
    }

    pub fn public(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            key_version: self.key_version,
            alg: ALG.to_string(),
            key: self.pk.clone(),
        }
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Blind-sign every blinded message in a request. Crypto only — callers
    /// must apply the attestation gate first (see [`gate::issue_gated`]).
    pub fn blind_sign(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        if req.key_version != self.key_version {
            return Err(Error::KeyVersion {
                want: req.key_version,
                have: self.key_version,
            });
        }
        let mut sigs = Vec::with_capacity(req.blinded.len());
        for b in &req.blinded {
            sigs.push(self.sk.blind_sign(b)?);
        }
        Ok(SignResponse { blind_sigs: sigs })
    }
}

/// The issuance request a client sends to the issuer's `/sign` endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub token_challenge: TokenChallenge,
    pub key_version: u32,
    pub blinded: Vec<BlindMessage>,
    #[serde(with = "serdehelp::hex32")]
    pub binding: [u8; 32],
}

impl SignRequest {
    /// The channel-binding value the attestation must commit to.
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
}

/// The issuer's response: one blind signature per blinded message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignResponse {
    pub blind_sigs: Vec<BlindSignature>,
}

/// A finalized, publicly-verifiable token (RFC 9578 token type `0x0002`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub token_type: u16,
    #[serde(with = "serdehelp::hex32")]
    pub nonce: [u8; 32],
    #[serde(with = "serdehelp::hex32")]
    pub challenge_digest: [u8; 32],
    #[serde(with = "serdehelp::hex32")]
    pub token_key_id: [u8; 32],
    pub authenticator: Signature,
}

impl Token {
    /// RFC 9578 byte form: `token_type ‖ nonce ‖ challenge_digest ‖
    /// token_key_id ‖ authenticator`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let auth: &[u8] = self.authenticator.as_ref();
        let mut v = Vec::with_capacity(2 + 32 + 32 + 32 + auth.len());
        v.extend_from_slice(&self.token_type.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.challenge_digest);
        v.extend_from_slice(&self.token_key_id);
        v.extend_from_slice(auth);
        v
    }

    /// Parse the RFC 9578 byte form. `authenticator` is whatever remains after
    /// the fixed 98-byte prefix.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 2 + 32 + 32 + 32 + 1 {
            return Err(Error::Malformed(format!(
                "token too short: {} bytes",
                b.len()
            )));
        }
        let token_type = u16::from_be_bytes([b[0], b[1]]);
        let mut nonce = [0u8; 32];
        let mut challenge_digest = [0u8; 32];
        let mut token_key_id = [0u8; 32];
        nonce.copy_from_slice(&b[2..34]);
        challenge_digest.copy_from_slice(&b[34..66]);
        token_key_id.copy_from_slice(&b[66..98]);
        Ok(Token {
            token_type,
            nonce,
            challenge_digest,
            token_key_id,
            authenticator: Signature(b[98..].to_vec()),
        })
    }

    /// The token_input these claims sign over.
    fn input(&self) -> Vec<u8> {
        token_input(&self.nonce, &self.challenge_digest, &self.token_key_id)
    }
}

/// Client-held state between blinding and finalization. Keep this private; it
/// holds the blinding secrets that preserve unlinkability.
pub struct PendingTokens {
    challenge_digest: [u8; 32],
    token_key_id: [u8; 32],
    items: Vec<(BlindingResult, [u8; 32])>,
}

impl PendingTokens {
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The client side of the protocol.
pub struct Client;

impl Client {
    /// Blind `count` fresh token inputs for `challenge`, producing a request to
    /// send to the issuer and the secret state needed to finalize the result.
    ///
    /// ## Issuance batching (E.9)
    ///
    /// One hardware attestation can authorize a *batch* of `count` tokens. This
    /// amortizes the cost of producing a fresh quote against the origin's
    /// rate-limit policy: pick `count` to cover a session's expected redemptions
    /// without exceeding the per-attestation quota the issuer enforces (see
    /// [`ratelimit`]). Larger batches reduce attestation overhead but widen the
    /// blast radius of a single compromised client, so the issuer caps it.
    pub fn begin(
        pk: &IssuerPublicKey,
        challenge: &TokenChallenge,
        count: usize,
    ) -> Result<(SignRequest, PendingTokens), Error> {
        let challenge_digest = challenge.digest();
        let token_key_id = pk.token_key_id()?;
        let mut items = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let nonce = random_nonce()?;
            let msg = token_input(&nonce, &challenge_digest, &token_key_id);
            let br = pk.key.blind(&mut DefaultRng, &msg)?;
            blinded.push(br.blind_message.clone());
            items.push((br, nonce));
        }
        let binding = binding_of(&blinded);
        let req = SignRequest {
            token_challenge: challenge.clone(),
            key_version: pk.key_version,
            blinded,
            binding,
        };
        Ok((
            req,
            PendingTokens {
                challenge_digest,
                token_key_id,
                items,
            },
        ))
    }
}

impl PendingTokens {
    /// Finalize the issuer's blind signatures into usable tokens.
    pub fn finalize(self, pk: &IssuerPublicKey, resp: &SignResponse) -> Result<Vec<Token>, Error> {
        if resp.blind_sigs.len() != self.items.len() {
            return Err(Error::CountMismatch {
                want: self.items.len(),
                got: resp.blind_sigs.len(),
            });
        }
        let mut out = Vec::with_capacity(self.items.len());
        for ((br, nonce), bs) in self.items.into_iter().zip(resp.blind_sigs.iter()) {
            let msg = token_input(&nonce, &self.challenge_digest, &self.token_key_id);
            // Deterministic profile: no message randomizer.
            let sig = pk.key.finalize(bs, &br, &msg)?;
            out.push(Token {
                token_type: TOKEN_TYPE_BLIND_RSA,
                nonce,
                challenge_digest: self.challenge_digest,
                token_key_id: self.token_key_id,
                authenticator: sig,
            });
        }
        Ok(out)
    }
}

/// The origin side: verify a presented token against the issuer public key.
/// Stateless on its own — pair it with a [`spend`] store for double-spend
/// protection.
pub struct Verifier {
    pub pk: IssuerPublicKey,
}

impl Verifier {
    pub fn new(pk: IssuerPublicKey) -> Self {
        Self { pk }
    }

    /// Verify `token` against the `challenge` it should have been issued for.
    /// Checks token type, that it commits to this challenge, that it is bound to
    /// our issuer key (E.4 pin), then verifies the blind-RSA authenticator.
    /// Returns the nonce (the unique spend identifier) on success.
    pub fn verify(&self, token: &Token, challenge: &TokenChallenge) -> Result<[u8; 32], Error> {
        if token.token_type != TOKEN_TYPE_BLIND_RSA {
            return Err(Error::TokenType {
                want: TOKEN_TYPE_BLIND_RSA,
                got: token.token_type,
            });
        }
        if token.challenge_digest != challenge.digest() {
            return Err(Error::ChallengeMismatch);
        }
        if token.token_key_id != self.pk.token_key_id()? {
            return Err(Error::KeyIdMismatch);
        }
        let msg = token.input();
        self.pk.key.verify(&token.authenticator, None, &msg)?;
        Ok(token.nonce)
    }
}

/// RFC 9577 HTTP authentication helpers for the `PrivateToken` scheme.
pub mod http {
    use super::{IssuerPublicKey, Token};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};

    /// Build a `WWW-Authenticate: PrivateToken challenge=…, token-key=…` value
    /// (RFC 9577 §2.2). `challenge_bytes` is `TokenChallenge::to_bytes()`.
    pub fn www_authenticate(
        challenge_bytes: &[u8],
        pk: &IssuerPublicKey,
    ) -> Result<String, super::Error> {
        let spki = pk.key.to_spki().map_err(super::Error::from)?;
        Ok(format!(
            "PrivateToken challenge={}, token-key={}",
            B64URL.encode(challenge_bytes),
            B64URL.encode(spki),
        ))
    }

    /// Build an `Authorization: PrivateToken token=…` value (RFC 9577 §2.3).
    pub fn authorization(token: &Token) -> String {
        format!("PrivateToken token={}", B64URL.encode(token.to_bytes()))
    }

    /// Parse a token out of an `Authorization: PrivateToken token=…` value.
    pub fn parse_authorization(header: &str) -> Result<Token, super::Error> {
        let rest = header
            .trim()
            .strip_prefix("PrivateToken")
            .ok_or_else(|| super::Error::Malformed("not a PrivateToken auth header".into()))?
            .trim();
        let b64 = rest
            .split("token=")
            .nth(1)
            .map(|s| s.trim().trim_matches('"').trim_end_matches(','))
            .ok_or_else(|| super::Error::Malformed("missing token= parameter".into()))?;
        let bytes = B64URL
            .decode(b64)
            .map_err(|e| super::Error::Malformed(format!("base64url: {e}")))?;
        Token::from_bytes(&bytes)
    }
}
