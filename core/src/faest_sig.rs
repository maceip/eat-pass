//! FAEST-128f signatures for attester authorization, KT log, and policy sidecars.

use faest::{
    ByteEncoding, FAEST128fSignature, FAEST128fSigningKey, FAEST128fVerificationKey, Keypair,
    KeypairGenerator, Signer, Verifier,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use crate::Error;

pub const FAEST_PK_LEN: usize = 32;

pub fn signing_key_from_seed(seed: [u8; 32]) -> Result<FAEST128fSigningKey, Error> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    Ok(FAEST128fSigningKey::generate(&mut rng))
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<FAEST128fVerificationKey, Error> {
    FAEST128fVerificationKey::try_from(bytes.as_slice())
        .map_err(|e| Error::Faest(format!("verifying key: {e}")))
}

pub fn verifying_key_from_hex(hex_str: &str) -> Result<FAEST128fVerificationKey, Error> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| Error::Faest(format!("pub hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Faest("pub key must be 32 bytes (64 hex chars)".into()))?;
    verifying_key_from_bytes(&arr)
}

pub fn sign(sk: &FAEST128fSigningKey, msg: &[u8]) -> Vec<u8> {
    Signer::<FAEST128fSignature>::sign(sk, msg)
        .as_ref()
        .to_vec()
}

pub fn public_bytes_from_sk(sk: &FAEST128fSigningKey) -> [u8; FAEST_PK_LEN] {
    public_bytes(&Keypair::verifying_key(sk))
}

pub fn verify(vk: &FAEST128fVerificationKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let sig = FAEST128fSignature::try_from(sig)
        .map_err(|e| Error::Faest(format!("signature decode: {e}")))?;
    vk.verify(msg, &sig)
        .map_err(|e| Error::Faest(format!("signature verify: {e}")))
}

pub fn public_bytes(vk: &FAEST128fVerificationKey) -> [u8; FAEST_PK_LEN] {
    vk.to_bytes()
}
