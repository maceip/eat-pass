//! PoMFRIT blind signatures for eat-pass spend tokens.
//!
//! Construction: optimized MAYO1 + VOLE-in-the-head (FV1_128), USENIX Sec 2026 /
//! ePrint 2026/109. Requires native build of `mayo-c-sys` and `vole-mayo-sys`
//! (Linux x86_64, meson, ninja). See `eat-pass/scripts/build-pomfrit-deps.sh`.

use blind_signatures::blind_sig_optimized::BlindSignatureOptimized;
use blind_signatures::zk::vole_mayo::proof_state::{VOLEMAYOProof, VOLEMAYOProofState};
use blind_signatures::zk::ZKType;
use rand::RngCore;
use thiserror::Error;

pub const ALG: &str = "PoMFRIT-MAYO1-FV1-128";
/// eat-pass token type (not RFC 9578 `0x0002`).
pub const TOKEN_TYPE: u16 = 0x4550;

const ADDITIONAL_R_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum PomfritError {
    #[error("count mismatch: want {want}, got {got}")]
    CountMismatch { want: usize, got: usize },
    #[error("malformed token: {0}")]
    Malformed(String),
    #[error("verification failed")]
    VerifyFailed,
}

pub struct Scheme {
    inner: BlindSignatureOptimized,
}

impl Scheme {
    pub fn new() -> Self {
        Self {
            inner: BlindSignatureOptimized::setup(ZKType::FV1_128),
        }
    }

    pub fn keygen(&self) -> KeyMaterial {
        let (pk, sk) = self.inner.keygen();
        let epk = self.inner.mayo.expand_pk(&pk);
        KeyMaterial { pk, sk, epk }
    }

    pub fn expand_pk(&self, pk: &[u8]) -> Vec<u8> {
        let pk = pk.to_vec();
        self.inner.mayo.expand_pk(&pk)
    }

    pub fn token_key_id(pk: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(pk).into()
    }

    pub fn client_begin(
        &self,
        pk: &[u8],
        token_key_id: &[u8; 32],
        challenge_digest: &[u8; 32],
        count: usize,
    ) -> (SignRequest, PendingMint) {
        let mut blinded = Vec::with_capacity(count);
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let nonce = random32();
            let msg = token_input(&nonce, challenge_digest, token_key_id);
            let mut additional_r = random32();
            let (bm, state) = self.inner.sign_1(&msg, &mut additional_r);
            blinded.push(bm);
            items.push(PendingItem {
                state,
                nonce,
                additional_r,
            });
        }
        let binding = binding_of(&blinded);
        (
            SignRequest { blinded, binding },
            PendingMint {
                pk: pk.to_vec(),
                challenge_digest: *challenge_digest,
                token_key_id: *token_key_id,
                items,
            },
        )
    }

    pub fn issuer_sign(&self, sk: &[u8], req: &SignRequest) -> SignResponse {
        let sk = sk.to_vec();
        let mut blind_sigs = Vec::with_capacity(req.blinded.len());
        for bm in &req.blinded {
            blind_sigs.push(self.inner.sign_2(&sk, bm));
        }
        SignResponse { blind_sigs }
    }

    pub fn client_finalize(
        &self,
        pending: PendingMint,
        resp: &SignResponse,
        pk: &[u8],
    ) -> Result<Vec<SpendToken>, PomfritError> {
        if pk != pending.pk.as_slice() {
            return Err(PomfritError::Malformed("issuer pubkey mismatch".into()));
        }
        if resp.blind_sigs.len() != pending.items.len() {
            return Err(PomfritError::CountMismatch {
                want: pending.items.len(),
                got: resp.blind_sigs.len(),
            });
        }
        let epk = self.inner.mayo.expand_pk(&pending.pk);
        let mut out = Vec::with_capacity(pending.items.len());
        for (item, bsig) in pending.items.into_iter().zip(resp.blind_sigs.iter()) {
            let mut additional_r = item.additional_r;
            let proof = self.inner.sign_3(
                &pending.pk,
                &epk,
                bsig,
                item.state,
                &mut additional_r,
            );
            let authenticator = encode_authenticator(&additional_r, &proof);
            out.push(SpendToken {
                token_type: TOKEN_TYPE,
                nonce: item.nonce,
                challenge_digest: pending.challenge_digest,
                token_key_id: pending.token_key_id,
                authenticator,
            });
        }
        Ok(out)
    }

    pub fn verify(
        &self,
        epk: &[u8],
        token: &SpendToken,
    ) -> Result<[u8; 32], PomfritError> {
        if token.token_type != TOKEN_TYPE {
            return Err(PomfritError::Malformed(format!(
                "token type {} unsupported (want {TOKEN_TYPE})",
                token.token_type
            )));
        }
        let (additional_r, proof) = decode_authenticator(&token.authenticator)?;
        let msg = token_input(
            &token.nonce,
            &token.challenge_digest,
            &token.token_key_id,
        );
        let mut additional_r = additional_r;
        if !self.inner.verify(epk, &msg, &proof, &mut additional_r) {
            return Err(PomfritError::VerifyFailed);
        }
        Ok(token.nonce)
    }
}

impl Default for Scheme {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KeyMaterial {
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    pub epk: Vec<u8>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignRequest {
    #[serde(with = "b64vec")]
    pub blinded: Vec<Vec<u8>>,
    #[serde(with = "hex32")]
    pub binding: [u8; 32],
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignResponse {
    #[serde(with = "b64vec")]
    pub blind_sigs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SpendToken {
    pub token_type: u16,
    #[serde(with = "hex32")]
    pub nonce: [u8; 32],
    #[serde(with = "hex32")]
    pub challenge_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub token_key_id: [u8; 32],
    #[serde(with = "b64bytes")]
    pub authenticator: Vec<u8>,
}

impl SpendToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(98 + self.authenticator.len());
        v.extend_from_slice(&self.token_type.to_be_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.challenge_digest);
        v.extend_from_slice(&self.token_key_id);
        v.extend_from_slice(&self.authenticator);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, PomfritError> {
        if b.len() < 98 + ADDITIONAL_R_LEN + 1 {
            return Err(PomfritError::Malformed(format!(
                "token too short: {} bytes",
                b.len()
            )));
        }
        Ok(Self {
            token_type: u16::from_be_bytes([b[0], b[1]]),
            nonce: b[2..34].try_into().unwrap(),
            challenge_digest: b[34..66].try_into().unwrap(),
            token_key_id: b[66..98].try_into().unwrap(),
            authenticator: b[98..].to_vec(),
        })
    }
}

pub struct PendingMint {
    pk: Vec<u8>,
    challenge_digest: [u8; 32],
    token_key_id: [u8; 32],
    items: Vec<PendingItem>,
}

impl PendingMint {
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

struct PendingItem {
    state: VOLEMAYOProofState,
    nonce: [u8; 32],
    additional_r: [u8; 32],
}

pub fn token_input(
    nonce: &[u8; 32],
    challenge_digest: &[u8; 32],
    token_key_id: &[u8; 32],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + 96);
    v.extend_from_slice(&TOKEN_TYPE.to_be_bytes());
    v.extend_from_slice(nonce);
    v.extend_from_slice(challenge_digest);
    v.extend_from_slice(token_key_id);
    v
}

const BINDING_DOMAIN: &[u8] = b"eat-pass/binding\0";

pub fn binding_of(blinded: &[Vec<u8>]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(BINDING_DOMAIN);
    h.update((blinded.len() as u32).to_be_bytes());
    for b in blinded {
        h.update((b.len() as u32).to_be_bytes());
        h.update(b);
    }
    h.finalize().into()
}

fn encode_authenticator(additional_r: &[u8; 32], proof: &VOLEMAYOProof) -> Vec<u8> {
    let mut v = Vec::with_capacity(32 + proof.proof.len());
    v.extend_from_slice(additional_r);
    v.extend_from_slice(&proof.proof);
    v
}

fn decode_authenticator(bytes: &[u8]) -> Result<([u8; 32], VOLEMAYOProof), PomfritError> {
    if bytes.len() <= ADDITIONAL_R_LEN {
        return Err(PomfritError::Malformed("authenticator too short".into()));
    }
    let mut additional_r = [0u8; 32];
    additional_r.copy_from_slice(&bytes[..ADDITIONAL_R_LEN]);
    Ok((
        additional_r,
        VOLEMAYOProof {
            proof: bytes[ADDITIONAL_R_LEN..].to_vec(),
        },
    ))
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rng().fill_bytes(&mut b);
    b
}

mod b64bytes {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.trim()).map_err(serde::de::Error::custom)
    }
}

mod b64vec {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let enc: Vec<String> = v.iter().map(|b| B64.encode(b)).collect();
        enc.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        let enc: Vec<String> = Vec::deserialize(d)?;
        enc.into_iter()
            .map(|s| B64.decode(s.trim()).map_err(serde::de::Error::custom))
            .collect()
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}
