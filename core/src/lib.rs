//! eat-pass-core — attestation-gated, unlinkable authorization tokens.
//!
//! Spend credentials are **PoMFRIT** blind signatures (MAYO1 + VOLE-in-the-head).
//! Attester authorization, key-transparency, and policy sidecars use **FAEST-128f**.

pub mod authorize;
pub mod faest_sig;
pub mod gate;
pub mod ratelimit;
mod serdehelp;
pub mod spend;
pub mod transparency;

use eat_pass_pomfrit::{
    self as pomfrit, binding_of as pomfrit_binding_of, Scheme, SpendToken, SignRequest as PomfritSignBody,
    SignResponse as PomfritSignResponse, TOKEN_TYPE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use pomfrit::ALG as POMFRIT_ALG;
pub use pomfrit::TOKEN_TYPE as TOKEN_TYPE_POMFRIT;

const BINDING_DOMAIN: &[u8] = b"eat-pass/binding\0";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("pomfrit: {0}")]
    Pomfrit(#[from] pomfrit::PomfritError),
    #[error("faest: {0}")]
    Faest(String),
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

/// PoMFRIT profile identifier published at `/keys`.
pub const ALG: &str = pomfrit::ALG;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenChallenge {
    pub token_type: u16,
    pub issuer_name: String,
    #[serde(with = "serdehelp::b64vec")]
    pub redemption_context: Vec<u8>,
    pub origin_info: String,
}

impl TokenChallenge {
    pub fn new(issuer_name: impl Into<String>, origin_info: impl Into<String>) -> Self {
        Self {
            token_type: TOKEN_TYPE,
            issuer_name: issuer_name.into(),
            redemption_context: Vec::new(),
            origin_info: origin_info.into(),
        }
    }

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

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 2 + 2 + 1 + 2 {
            return Err(Error::Malformed("challenge too short".into()));
        }
        let mut off = 0;
        let token_type = u16::from_be_bytes([b[off], b[off + 1]]);
        off += 2;
        let iss_len = u16::from_be_bytes([b[off], b[off + 1]]) as usize;
        off += 2;
        if off + iss_len + 1 + 2 > b.len() {
            return Err(Error::Malformed("challenge issuer truncated".into()));
        }
        let issuer_name = std::str::from_utf8(&b[off..off + iss_len])
            .map_err(|e| Error::Malformed(format!("challenge issuer utf8: {e}")))?
            .to_string();
        off += iss_len;
        let ctx_len = b[off] as usize;
        off += 1;
        if off + ctx_len + 2 > b.len() {
            return Err(Error::Malformed("challenge context truncated".into()));
        }
        let redemption_context = b[off..off + ctx_len].to_vec();
        off += ctx_len;
        let org_len = u16::from_be_bytes([b[off], b[off + 1]]) as usize;
        off += 2;
        if off + org_len != b.len() {
            return Err(Error::Malformed("challenge origin truncated".into()));
        }
        let origin_info = std::str::from_utf8(&b[off..off + org_len])
            .map_err(|e| Error::Malformed(format!("challenge origin utf8: {e}")))?
            .to_string();
        Ok(Self {
            token_type,
            issuer_name,
            redemption_context,
            origin_info,
        })
    }

    pub fn with_redemption_context(mut self, ctx: [u8; 32]) -> Self {
        self.redemption_context = ctx.to_vec();
        self
    }

    pub fn with_random_redemption_context(self) -> Result<Self, Error> {
        Ok(self.with_redemption_context(random_nonce()?))
    }

    pub fn has_redemption_context(&self) -> bool {
        self.redemption_context.len() == 32
    }
}

pub fn binding_of(blinded: &[Vec<u8>]) -> [u8; 32] {
    pomfrit_binding_of(blinded)
}

pub(crate) fn random_nonce() -> Result<[u8; 32], Error> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(n)
}

pub fn token_key_id(pk_bytes: &[u8]) -> [u8; 32] {
    Scheme::token_key_id(pk_bytes)
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    pub key_version: u32,
    pub alg: String,
    #[serde(with = "serdehelp::b64vec")]
    pub key: Vec<u8>,
}

impl IssuerPublicKey {
    pub fn token_key_id(&self) -> Result<[u8; 32], Error> {
        Ok(token_key_id(&self.key))
    }

    pub fn expanded_key(&self) -> Vec<u8> {
        Scheme::new().expand_pk(&self.key)
    }
}

pub fn check_key_consistency(pinned: &[u8; 32], pk: &IssuerPublicKey) -> Result<(), Error> {
    if &pk.token_key_id()? == pinned {
        Ok(())
    } else {
        Err(Error::KeyIdMismatch)
    }
}

pub struct Issuer {
    sk: Vec<u8>,
    pk: Vec<u8>,
    key_version: u32,
}

impl Issuer {
    pub fn generate(key_version: u32) -> Self {
        let scheme = Scheme::new();
        let kp = scheme.keygen();
        Self {
            sk: kp.sk,
            pk: kp.pk,
            key_version,
        }
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

    pub fn blind_sign(&self, req: &SignRequest) -> Result<SignResponse, Error> {
        if req.key_version != self.key_version {
            return Err(Error::KeyVersion {
                want: req.key_version,
                have: self.key_version,
            });
        }
        Ok(SignResponse {
            blind_sigs: Scheme::new()
                .issuer_sign(&self.sk, &req.body)
                .blind_sigs,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub token_challenge: TokenChallenge,
    pub key_version: u32,
    #[serde(flatten)]
    pub body: PomfritSignBody,
}

impl SignRequest {
    pub fn binding(&self) -> [u8; 32] {
        self.body.binding
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignResponse {
    #[serde(with = "serdehelp::b64vec_nested")]
    pub blind_sigs: Vec<Vec<u8>>,
}

pub type Token = SpendToken;

pub struct PendingTokens {
    inner: pomfrit::PendingMint,
    pk: IssuerPublicKey,
}

impl PendingTokens {
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

pub struct Client;

impl Client {
    pub fn begin(
        pk: &IssuerPublicKey,
        challenge: &TokenChallenge,
        count: usize,
    ) -> Result<(SignRequest, PendingTokens), Error> {
        let challenge_digest = challenge.digest();
        let token_key_id = pk.token_key_id()?;
        let scheme = Scheme::new();
        let (body, inner) =
            scheme.client_begin(&pk.key, &token_key_id, &challenge_digest, count);
        let req = SignRequest {
            token_challenge: challenge.clone(),
            key_version: pk.key_version,
            body,
        };
        Ok((
            req,
            PendingTokens {
                inner,
                pk: pk.clone(),
            },
        ))
    }
}

impl PendingTokens {
    pub fn finalize(self, pk: &IssuerPublicKey, resp: &SignResponse) -> Result<Vec<Token>, Error> {
        let scheme = Scheme::new();
        let pomfrit_resp = PomfritSignResponse {
            blind_sigs: resp.blind_sigs.clone(),
        };
        scheme
            .client_finalize(
                self.inner,
                &pomfrit_resp,
                &pk.key,
            )
            .map_err(Error::from)
    }
}

pub struct Verifier {
    pub pk: IssuerPublicKey,
    epk: Vec<u8>,
}

impl Verifier {
    pub fn new(pk: IssuerPublicKey) -> Self {
        let epk = Scheme::new().expand_pk(&pk.key);
        Self { pk, epk }
    }

    pub fn verify(&self, token: &Token, challenge: &TokenChallenge) -> Result<[u8; 32], Error> {
        if token.token_type != TOKEN_TYPE {
            return Err(Error::TokenType {
                want: TOKEN_TYPE,
                got: token.token_type,
            });
        }
        if token.challenge_digest != challenge.digest() {
            return Err(Error::ChallengeMismatch);
        }
        if token.token_key_id != self.pk.token_key_id()? {
            return Err(Error::KeyIdMismatch);
        }
        Scheme::new()
            .verify(&self.epk, token)
            .map_err(Error::from)
    }
}

pub mod http {
    use super::{IssuerPublicKey, Token};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};

    pub fn www_authenticate(
        challenge_bytes: &[u8],
        pk: &IssuerPublicKey,
    ) -> Result<String, super::Error> {
        Ok(format!(
            "PrivateToken challenge={}, token-key={}",
            B64URL.encode(challenge_bytes),
            B64URL.encode(&pk.key),
        ))
    }

    pub fn authorization(token: &Token) -> String {
        format!("PrivateToken token={}", B64URL.encode(token.to_bytes()))
    }

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
        Token::from_bytes(&bytes).map_err(super::Error::from)
    }

    pub fn parse_www_authenticate(header: &str) -> Result<super::TokenChallenge, super::Error> {
        let rest = header
            .trim()
            .strip_prefix("PrivateToken")
            .ok_or_else(|| super::Error::Malformed("not a PrivateToken challenge".into()))?
            .trim();
        let challenge_b64 = rest
            .split("challenge=")
            .nth(1)
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().trim_matches('"'))
            .ok_or_else(|| super::Error::Malformed("missing challenge= parameter".into()))?;
        let bytes = B64URL
            .decode(challenge_b64)
            .map_err(|e| super::Error::Malformed(format!("challenge base64url: {e}")))?;
        super::TokenChallenge::from_bytes(&bytes)
    }
}
