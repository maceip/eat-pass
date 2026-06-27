//! eat-pass-core — attestation-gated, unlinkable authorization tokens.
//!
//! The credential is an RSA blind signature (RFC 9474, RSABSSA-SHA384-PSS-
//! Randomized) over a client-chosen nonce. An issuer blind-signs the nonce
//! without seeing it, so a finalized token cannot be linked to its issuance.
//! Issuance is meant to be *gated* on attestation: see [`gate`].
//!
//! Roles:
//! - [`Client`] blinds nonces and finalizes tokens.
//! - [`Issuer`] holds the keypair and blind-signs (crypto only; the gate lives
//!   in [`gate`]).
//! - [`Verifier`] (an origin) checks a token with nothing but the public key.

pub mod gate;
mod serdehelp;

use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng,
    KeyPairSha384PSSRandomized as KeyPair, MessageRandomizer,
    PublicKeySha384PSSRandomized as RsaPublicKey, SecretKeySha384PSSRandomized as RsaSecretKey,
    Signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// RFC 9474 profile we issue under.
pub const ALG: &str = "RSABSSA-SHA384-PSS-Randomized";
/// Default issuer modulus size.
pub const DEFAULT_MODULUS_BITS: usize = 3072;

const MSG_DOMAIN: &[u8] = b"eat-pass/v0/token\0";
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
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl From<blind_rsa_signatures::Error> for Error {
    fn from(e: blind_rsa_signatures::Error) -> Self {
        Error::Brs(e.to_string())
    }
}

/// Domain-separator binding tokens to an application use-case. A token minted
/// for use-case A cannot be redeemed for use-case B.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UseCase(pub String);

impl UseCase {
    pub fn new(s: impl Into<String>) -> Self {
        UseCase(s.into())
    }
}

fn token_message(use_case: &UseCase, nonce: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MSG_DOMAIN.len() + use_case.0.len() + 33);
    m.extend_from_slice(MSG_DOMAIN);
    m.extend_from_slice(use_case.0.as_bytes());
    m.push(0);
    m.extend_from_slice(nonce);
    m
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

fn random_nonce() -> Result<[u8; 32], Error> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).map_err(|e| Error::Rng(e.to_string()))?;
    Ok(n)
}

/// The issuer's public key, as published at `/keys`.
#[derive(Clone, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    pub key_version: u32,
    pub alg: String,
    pub key: RsaPublicKey,
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
    pub use_case: UseCase,
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

/// A finalized, publicly-verifiable token the client presents to an origin.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Token {
    pub use_case: UseCase,
    #[serde(with = "serdehelp::hex32")]
    pub nonce: [u8; 32],
    pub msg_randomizer: Option<MessageRandomizer>,
    pub sig: Signature,
}

/// Client-held state between blinding and finalization. Keep this private; it
/// holds the blinding secrets that preserve unlinkability.
pub struct PendingTokens {
    use_case: UseCase,
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
    /// Blind `count` fresh random nonces for `use_case`, producing a request to
    /// send to the issuer and the secret state needed to finalize the result.
    pub fn begin(
        pk: &IssuerPublicKey,
        use_case: &UseCase,
        count: usize,
    ) -> Result<(SignRequest, PendingTokens), Error> {
        let mut items = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let nonce = random_nonce()?;
            let msg = token_message(use_case, &nonce);
            let br = pk.key.blind(&mut DefaultRng, &msg)?;
            blinded.push(br.blind_message.clone());
            items.push((br, nonce));
        }
        let binding = binding_of(&blinded);
        let req = SignRequest {
            use_case: use_case.clone(),
            key_version: pk.key_version,
            blinded,
            binding,
        };
        Ok((
            req,
            PendingTokens {
                use_case: use_case.clone(),
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
            let msg = token_message(&self.use_case, &nonce);
            let sig = pk.key.finalize(bs, &br, &msg)?;
            out.push(Token {
                use_case: self.use_case.clone(),
                nonce,
                msg_randomizer: br.msg_randomizer.clone(),
                sig,
            });
        }
        Ok(out)
    }
}

/// The origin side: verify a presented token against the issuer public key.
/// Stateless on its own — pair it with a spent-nonce store for double-spend
/// protection.
pub struct Verifier {
    pub pk: IssuerPublicKey,
}

impl Verifier {
    pub fn new(pk: IssuerPublicKey) -> Self {
        Self { pk }
    }

    /// Verify `token`'s signature for its use-case + nonce. Returns the nonce
    /// (the unique spend identifier) on success.
    pub fn verify(&self, token: &Token, expected_use_case: &UseCase) -> Result<[u8; 32], Error> {
        if &token.use_case != expected_use_case {
            return Err(Error::Brs("use-case mismatch".into()));
        }
        let msg = token_message(&token.use_case, &token.nonce);
        self.pk
            .key
            .verify(&token.sig, token.msg_randomizer.clone(), &msg)?;
        Ok(token.nonce)
    }
}
