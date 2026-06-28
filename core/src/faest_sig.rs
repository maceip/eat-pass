//! FAEST-128f signatures for attester authorization, KT log, and policy sidecars.

use faest::{FAEST128fSignature, FAEST128fSigningKey, FAEST128fVerifyingKey};
use signature::{Signer, Verifier};

use crate::Error;

pub const FAEST_PK_LEN: usize = 32;

pub fn signing_key_from_seed(seed: [u8; 32]) -> Result<FAEST128fSigningKey, Error> {
    FAEST128fSigningKey::try_from(seed.as_slice()).map_err(|e| Error::Faest(format!("signing key: {e}")))
}

pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<FAEST128fVerifyingKey, Error> {
    FAEST128fVerifyingKey::try_from(bytes.as_slice())
        .map_err(|e| Error::Faest(format!("verifying key: {e}")))
}

pub fn verifying_key_from_hex(hex_str: &str) -> Result<FAEST128fVerifyingKey, Error> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| Error::Faest(format!("pub hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Faest("pub key must be 32 bytes (64 hex chars)".into()))?;
    verifying_key_from_bytes(&arr)
}

pub fn sign(sk: &FAEST128fSigningKey, msg: &[u8]) -> Vec<u8> {
    sk.sign(msg).to_bytes().to_vec()
}

pub fn verify(vk: &FAEST128fVerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let sig = FAEST128fSignature::try_from(sig)
        .map_err(|e| Error::Faest(format!("signature decode: {e}")))?;
    vk.verify(msg, &sig)
        .map_err(|e| Error::Faest(format!("signature verify: {e}")))
}

pub fn public_bytes(vk: &FAEST128fVerifyingKey) -> [u8; FAEST_PK_LEN] {
    vk.to_bytes()
}
