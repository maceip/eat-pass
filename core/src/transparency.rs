//! Key transparency (E.4, second half).
//!
//! [`token_key_id`](crate::token_key_id) + [`check_key_consistency`](crate::check_key_consistency)
//! let a client pin *one* issuer key and detect a split-view issuer that serves
//! a different key to deanonymize it. But "pin one key" begs the question: how
//! does a client learn the *right* key, and how does it notice a silent rotation
//! to an attacker key? This module answers that with a small, gossip-able
//! **append-only key log**:
//!
//! - The log operator publishes a hash-chained list of [`KeyRecord`]s, one per
//!   issuer key it has ever vouched for, and an ed25519-[`SignedHead`] over the
//!   chain head. Clients pin the *log's* public key (one key, long-lived,
//!   auditable) instead of every issuer key.
//! - A client [`verify_log`]s the served records against the signed head
//!   (so the operator cannot serve records that differ from what it committed),
//!   then [`verify_inclusion`] confirms the key the issuer is currently serving
//!   (`/keys` → `token_key_id`) is actually in the log. An issuer key absent
//!   from the log is refused.
//! - Across time a client calls [`verify_consistency`] between the head it saw
//!   last and the new head: the new chain must *extend* the old one (the old
//!   head must reappear as an intermediate head). This catches an equivocating
//!   operator that rewrites history to hide a key it briefly served.
//!
//! This is a deliberately linear hash chain rather than an RFC 6962 Merkle tree:
//! issuer keys rotate rarely (O(tens) of records), so shipping the whole record
//! list is cheap and the proofs are trivial to audit by hand. The domain
//! separators below make leaf, chain-step, and signed-head hashing unambiguous.

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::faest_sig::{self, signing_key_from_seed};
use crate::IssuerPublicKey;

const LEAF_DOMAIN: &[u8] = b"eat-pass/kt/leaf\0";
const HEAD_DOMAIN: &[u8] = b"eat-pass/kt/head\0";
const STH_DOMAIN: &[u8] = b"eat-pass/kt/sth\0";

/// Errors from building or checking a key log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransparencyError {
    #[error("bad hex in {0}")]
    Hex(&'static str),
    #[error("record {field} wrong length")]
    Length { field: &'static str },
    #[error("signed head does not match the served records")]
    HeadMismatch,
    #[error("signed-head seq {sth} != record count {records}")]
    SeqMismatch { sth: u64, records: usize },
    #[error("signed-head signature invalid")]
    BadSignature,
    #[error("token_key_id not present in the log")]
    NotIncluded,
    #[error("new log does not extend the previously-seen head (history rewritten)")]
    NotConsistent,
}

/// One published key in the log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRecord {
    /// Position in the chain, 0-based.
    pub seq: u64,
    /// The issuer key_version this record vouches for.
    pub key_version: u32,
    /// `SHA256(SPKI)` of the issuer key — the same id pinned into tokens.
    pub token_key_id: String,
    /// Unix seconds the key becomes valid (informational / ordering aid).
    pub not_before: u64,
}

impl KeyRecord {
    fn token_key_id_bytes(&self) -> Result<[u8; 32], TransparencyError> {
        let v = hex::decode(self.token_key_id.trim())
            .map_err(|_| TransparencyError::Hex("token_key_id"))?;
        v.as_slice()
            .try_into()
            .map_err(|_| TransparencyError::Length {
                field: "token_key_id",
            })
    }

    /// Leaf hash bound to the record's fields (domain-separated).
    fn leaf_hash(&self) -> Result<[u8; 32], TransparencyError> {
        let tkid = self.token_key_id_bytes()?;
        let mut h = Sha256::new();
        h.update(LEAF_DOMAIN);
        h.update(self.seq.to_be_bytes());
        h.update(self.key_version.to_be_bytes());
        h.update(tkid);
        h.update(self.not_before.to_be_bytes());
        Ok(h.finalize().into())
    }
}

/// ed25519-signed commitment to the chain head at a point in time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedHead {
    /// Index of the last record covered (== records.len() - 1).
    pub seq: u64,
    /// Chain head hash (hex).
    pub head: String,
    /// FAEST-128f signature over `STH_DOMAIN || seq_be || head` (standard base64).
    pub sig: String,
}

/// The empty-chain head (before any record), domain-separated.
fn genesis_head() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HEAD_DOMAIN);
    h.update(b"genesis");
    h.finalize().into()
}

/// Fold one leaf into the running head.
fn step(prev: &[u8; 32], leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(HEAD_DOMAIN);
    h.update(prev);
    h.update(leaf);
    h.finalize().into()
}

/// Recompute every intermediate head for `records`. `heads[i]` is the head
/// after folding records `0..=i`; `heads.len() == records.len()`.
fn chain_heads(records: &[KeyRecord]) -> Result<Vec<[u8; 32]>, TransparencyError> {
    let mut heads = Vec::with_capacity(records.len());
    let mut cur = genesis_head();
    for r in records {
        cur = step(&cur, &r.leaf_hash()?);
        heads.push(cur);
    }
    Ok(heads)
}

/// The head over `records` (genesis if empty).
pub fn head_of(records: &[KeyRecord]) -> Result<[u8; 32], TransparencyError> {
    Ok(chain_heads(records)?
        .last()
        .copied()
        .unwrap_or_else(genesis_head))
}

/// Operator-side builder for the append-only log.
#[derive(Default)]
pub struct KeyLog {
    records: Vec<KeyRecord>,
}

impl KeyLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an issuer key. Returns the record's seq.
    pub fn append(
        &mut self,
        pk: &IssuerPublicKey,
        not_before: u64,
    ) -> Result<u64, TransparencyError> {
        let tkid = pk
            .token_key_id()
            .map_err(|_| TransparencyError::Hex("token_key_id"))?;
        let seq = self.records.len() as u64;
        self.records.push(KeyRecord {
            seq,
            key_version: pk.key_version,
            token_key_id: hex::encode(tkid),
            not_before,
        });
        Ok(seq)
    }

    pub fn records(&self) -> &[KeyRecord] {
        &self.records
    }

    pub fn head(&self) -> [u8; 32] {
        head_of(&self.records).expect("operator records are well-formed")
    }
}

/// The log operator's signing key (FAEST-128f). Clients pin [`LogSigner::public`].
pub struct LogSigner {
    sk: faest::FAEST128fSigningKey,
}

impl LogSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            sk: signing_key_from_seed(seed).expect("FAEST KT seed"),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        faest_sig::public_bytes(&self.sk.verifying_key())
    }

    pub fn sign(&self, log: &KeyLog) -> SignedHead {
        let head = log.head();
        let seq = log.records().len().saturating_sub(1) as u64;
        let msg = sth_message(seq, &head);
        let sig = faest_sig::sign(&self.sk, &msg);
        SignedHead {
            seq,
            head: hex::encode(head),
            sig: base64::engine::general_purpose::STANDARD.encode(sig),
        }
    }
}

fn sth_message(seq: u64, head: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(STH_DOMAIN.len() + 8 + 32);
    m.extend_from_slice(STH_DOMAIN);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(head);
    m
}

fn parse_head(sth: &SignedHead) -> Result<[u8; 32], TransparencyError> {
    let v = hex::decode(sth.head.trim()).map_err(|_| TransparencyError::Hex("head"))?;
    v.as_slice()
        .try_into()
        .map_err(|_| TransparencyError::Length { field: "head" })
}

/// Client check #1: the served `records` reproduce the `signed_head`, and the
/// head is genuinely signed by the pinned log key. After this returns Ok, the
/// records are exactly what the operator committed to.
pub fn verify_log(
    log_pub: &[u8; 32],
    records: &[KeyRecord],
    signed_head: &SignedHead,
) -> Result<(), TransparencyError> {
    if signed_head.seq as usize + 1 != records.len() {
        return Err(TransparencyError::SeqMismatch {
            sth: signed_head.seq,
            records: records.len(),
        });
    }
    let head = head_of(records)?;
    if head != parse_head(signed_head)? {
        return Err(TransparencyError::HeadMismatch);
    }
    let vk = faest_sig::verifying_key_from_bytes(log_pub)
        .map_err(|_| TransparencyError::BadSignature)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signed_head.sig.trim())
        .map_err(|_| TransparencyError::Hex("sig"))?;
    faest_sig::verify(&vk, &sth_message(signed_head.seq, &head), &sig_bytes)
        .map_err(|_| TransparencyError::BadSignature)?;
    Ok(())
}

/// Client check #2: the issuer key the client is about to use (its
/// `token_key_id`) is present in the verified log. Call [`verify_log`] first.
/// Returns the record seq on success.
pub fn verify_inclusion(
    records: &[KeyRecord],
    token_key_id: &[u8; 32],
) -> Result<u64, TransparencyError> {
    let want = hex::encode(token_key_id);
    records
        .iter()
        .find(|r| r.token_key_id.eq_ignore_ascii_case(&want))
        .map(|r| r.seq)
        .ok_or(TransparencyError::NotIncluded)
}

/// Client check #3 (across time): the `new_records`/`new_head` extend the
/// previously-seen `old` head — i.e. the old head reappears as the intermediate
/// head after `old.seq`. Detects an operator that rewrites earlier records.
/// Call [`verify_log`] on the new pair first.
pub fn verify_consistency(
    old: &SignedHead,
    new_records: &[KeyRecord],
) -> Result<(), TransparencyError> {
    let old_idx = old.seq as usize;
    if old_idx >= new_records.len() {
        // The new log is shorter than what we already saw — cannot extend it.
        return Err(TransparencyError::NotConsistent);
    }
    let heads = chain_heads(new_records)?;
    if heads[old_idx] != parse_head(old)? {
        return Err(TransparencyError::NotConsistent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Issuer;
    use std::sync::OnceLock;

    /// A pool of distinct 2048-bit issuer public keys, generated once and reused
    /// across tests (PoMFRIT keygen is the slow part).
    fn key_pool() -> &'static [IssuerPublicKey] {
        static POOL: OnceLock<Vec<IssuerPublicKey>> = OnceLock::new();
        POOL.get_or_init(|| {
            (0..6)
                .map(|v| Issuer::generate(v as u32 + 1).public())
                .collect()
        })
    }

    /// Distinct key by index; `key_version` overrides the published version.
    fn issuer_pk_idx(idx: usize, key_version: u32) -> IssuerPublicKey {
        let mut pk = key_pool()[idx].clone();
        pk.key_version = key_version;
        pk
    }

    fn issuer_pk(key_version: u32) -> IssuerPublicKey {
        let idx = (key_version as usize) % key_pool().len();
        issuer_pk_idx(idx, key_version)
    }

    #[test]
    fn build_sign_verify_roundtrip() {
        let signer = LogSigner::from_seed([7u8; 32]);
        let mut log = KeyLog::new();
        let k0 = issuer_pk(1);
        let k1 = issuer_pk(2);
        log.append(&k0, 1000).unwrap();
        log.append(&k1, 2000).unwrap();
        let sth = signer.sign(&log);

        verify_log(&signer.public(), log.records(), &sth).expect("log verifies");

        // Both keys are included.
        let seq0 = verify_inclusion(log.records(), &k0.token_key_id().unwrap()).unwrap();
        let seq1 = verify_inclusion(log.records(), &k1.token_key_id().unwrap()).unwrap();
        assert_eq!((seq0, seq1), (0, 1));
    }

    #[test]
    fn unknown_key_not_included() {
        let signer = LogSigner::from_seed([9u8; 32]);
        let mut log = KeyLog::new();
        log.append(&issuer_pk(1), 1).unwrap();
        let sth = signer.sign(&log);
        verify_log(&signer.public(), log.records(), &sth).unwrap();

        let stranger = issuer_pk(5).token_key_id().unwrap();
        assert_eq!(
            verify_inclusion(log.records(), &stranger),
            Err(TransparencyError::NotIncluded)
        );
    }

    #[test]
    fn tampered_record_breaks_head() {
        let signer = LogSigner::from_seed([1u8; 32]);
        let mut log = KeyLog::new();
        log.append(&issuer_pk(1), 1).unwrap();
        log.append(&issuer_pk(2), 2).unwrap();
        let sth = signer.sign(&log);

        // Operator (or MITM) swaps a record's key id after signing the head.
        let mut records = log.records().to_vec();
        records[0].token_key_id = hex::encode([0xEE; 32]);
        assert_eq!(
            verify_log(&signer.public(), &records, &sth),
            Err(TransparencyError::HeadMismatch)
        );
    }

    #[test]
    fn wrong_log_key_rejected() {
        let signer = LogSigner::from_seed([2u8; 32]);
        let mut log = KeyLog::new();
        log.append(&issuer_pk(1), 1).unwrap();
        let sth = signer.sign(&log);
        let attacker_pub = LogSigner::from_seed([3u8; 32]).public();
        assert_eq!(
            verify_log(&attacker_pub, log.records(), &sth),
            Err(TransparencyError::BadSignature)
        );
    }

    #[test]
    fn consistency_accepts_append_rejects_rewrite() {
        let signer = LogSigner::from_seed([4u8; 32]);
        let mut log = KeyLog::new();
        log.append(&issuer_pk(1), 1).unwrap();
        let old = signer.sign(&log);

        // Append a second key — old head must still appear at index 0.
        log.append(&issuer_pk(2), 2).unwrap();
        let new = signer.sign(&log);
        verify_log(&signer.public(), log.records(), &new).unwrap();
        verify_consistency(&old, log.records()).expect("append extends old head");

        // Now forge a log that rewrites record 0 — consistency must fail.
        let mut rewritten = KeyLog::new();
        rewritten.append(&issuer_pk(9), 1).unwrap();
        rewritten.append(&issuer_pk(2), 2).unwrap();
        assert_eq!(
            verify_consistency(&old, rewritten.records()),
            Err(TransparencyError::NotConsistent)
        );
    }

    #[test]
    fn multi_rotation_stays_consistent_from_every_prefix() {
        // Model three rotations (4 keys total). A client that saw *any* earlier
        // signed head must accept every later head as a consistent append.
        let signer = LogSigner::from_seed([5u8; 32]);
        let mut log = KeyLog::new();
        let mut heads = Vec::new();
        for v in 1..=4u32 {
            log.append(&issuer_pk(v), (v as u64) * 1000).unwrap();
            heads.push(signer.sign(&log));
        }
        let final_records = log.records().to_vec();
        verify_log(&signer.public(), &final_records, heads.last().unwrap()).unwrap();
        for (i, old) in heads.iter().enumerate() {
            verify_consistency(old, &final_records)
                .unwrap_or_else(|e| panic!("head after rotation {i} should extend: {e}"));
        }
        // The current key (v4) is included at the tail.
        let seq = verify_inclusion(&final_records, &issuer_pk(4).token_key_id().unwrap()).unwrap();
        assert_eq!(seq, 3);
    }
}
