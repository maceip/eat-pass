//! Partially-blind RSA issuance carrying a measurement **policy class** as
//! auditable public metadata (E.5 + E.6 — the design centerpiece).
//!
//! Plain blind-RSA hides the message *and* any policy: an origin can't tell
//! which build-class a token was issued for, and coarsening the anonymity set
//! to a class isn't expressible. Partially-blind RSA (RSAPBSSA) fixes this:
//! the issuer and client agree on **public metadata** that is folded into the
//! signature via a metadata-derived key, while the token (the nonce) stays
//! blind.
//!
//! We set the metadata to a [`PolicyClass`] — e.g. `"accepted-builds-v1"` — that
//! names a *set* of accepted measurements (the anonymity set, E.5). The result:
//!
//! - the **origin** sees only "this token was issued under policy X" (it must
//!   derive the per-policy key to verify), never the exact `value_x`;
//! - the **issuer** still cannot link a blinded request to a finalized token;
//! - the policy class is **auditable**: it is cryptographically bound, so an
//!   issuer can't later claim a token belonged to a different class.
//!
//! Anonymity is over everyone sharing a `(PolicyClass, key_version)` — far
//! larger than per-`value_x`, which is the whole point of E.5.

use blind_rsa_signatures::pbrsa::{
    PartiallyBlindKeyPairSha384PSSDeterministic as PbKeyPair,
    PartiallyBlindPublicKeySha384PSSDeterministic as PbPublicKey,
};
use blind_rsa_signatures::{BlindMessage, BlindSignature, BlindingResult, DefaultRng, Signature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{random_nonce, token_input, Error, TokenChallenge};

/// A named measurement policy class — the public metadata bound into a token.
/// Two builds in the same class are indistinguishable at redemption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyClass(pub String);

impl PolicyClass {
    pub fn new(s: impl Into<String>) -> Self {
        PolicyClass(s.into())
    }
    fn metadata(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// `token_key_id` for the partially-blind master key: SHA256 of its DER.
fn master_key_id(pk: &PbPublicKey) -> Result<[u8; 32], Error> {
    let der = pk.to_der().map_err(Error::from)?;
    Ok(Sha256::digest(&der).into())
}

/// The partially-blind issuer: a master keypair from which per-policy keys are
/// derived. Crypto only — the gate decides which policy a request qualifies for.
pub struct PbIssuer {
    kp: PbKeyPair,
    key_version: u32,
}

impl PbIssuer {
    pub fn generate(key_version: u32, modulus_bits: usize) -> Result<Self, Error> {
        let kp = PbKeyPair::generate(&mut DefaultRng, modulus_bits)?;
        Ok(Self { kp, key_version })
    }

    pub fn master_public(&self) -> PbMasterPublicKey {
        PbMasterPublicKey {
            key_version: self.key_version,
            key: self.kp.pk.clone(),
        }
    }

    pub fn key_version(&self) -> u32 {
        self.key_version
    }

    /// Blind-sign each blinded message under the key derived for `policy`.
    pub fn blind_sign(
        &self,
        blinded: &[BlindMessage],
        policy: &PolicyClass,
    ) -> Result<Vec<BlindSignature>, Error> {
        let sk = self
            .kp
            .derive_secret_key_for_metadata(policy.metadata())
            .map_err(Error::from)?;
        let mut out = Vec::with_capacity(blinded.len());
        for b in blinded {
            out.push(sk.blind_sign(b)?);
        }
        Ok(out)
    }
}

/// The master public key, published so clients/origins can derive per-policy
/// keys.
#[derive(Clone)]
pub struct PbMasterPublicKey {
    pub key_version: u32,
    pub key: PbPublicKey,
}

impl PbMasterPublicKey {
    pub fn token_key_id(&self) -> Result<[u8; 32], Error> {
        master_key_id(&self.key)
    }
}

/// A finalized partially-blind token. `policy` is public metadata (auditable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PbToken {
    pub policy: PolicyClass,
    #[serde(with = "crate::serdehelp::hex32")]
    pub nonce: [u8; 32],
    #[serde(with = "crate::serdehelp::hex32")]
    pub challenge_digest: [u8; 32],
    #[serde(with = "crate::serdehelp::hex32")]
    pub token_key_id: [u8; 32],
    pub authenticator: Signature,
}

/// Client secret state between blinding and finalization.
pub struct PbPending {
    policy: PolicyClass,
    challenge_digest: [u8; 32],
    token_key_id: [u8; 32],
    derived_pk: PbPublicKey,
    items: Vec<(BlindingResult, [u8; 32])>,
}

impl PbPending {
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// The partially-blind client.
pub struct PbClient;

impl PbClient {
    /// Blind `count` token inputs under `policy` for `challenge`.
    pub fn begin(
        master: &PbMasterPublicKey,
        policy: &PolicyClass,
        challenge: &TokenChallenge,
        count: usize,
    ) -> Result<(Vec<BlindMessage>, PbPending), Error> {
        let challenge_digest = challenge.digest();
        let token_key_id = master.token_key_id()?;
        let derived_pk = master
            .key
            .derive_public_key_for_metadata(policy.metadata())
            .map_err(Error::from)?;
        let mut items = Vec::with_capacity(count);
        let mut blinded = Vec::with_capacity(count);
        for _ in 0..count {
            let nonce = random_nonce()?;
            let msg = token_input(&nonce, &challenge_digest, &token_key_id);
            let br = derived_pk
                .blind(&mut DefaultRng, &msg, Some(policy.metadata()))
                .map_err(Error::from)?;
            blinded.push(br.blind_message.clone());
            items.push((br, nonce));
        }
        Ok((
            blinded,
            PbPending {
                policy: policy.clone(),
                challenge_digest,
                token_key_id,
                derived_pk,
                items,
            },
        ))
    }
}

impl PbPending {
    pub fn finalize(self, blind_sigs: &[BlindSignature]) -> Result<Vec<PbToken>, Error> {
        if blind_sigs.len() != self.items.len() {
            return Err(Error::CountMismatch {
                want: self.items.len(),
                got: blind_sigs.len(),
            });
        }
        let meta = self.policy.metadata().to_vec();
        let mut out = Vec::with_capacity(self.items.len());
        for ((br, nonce), bs) in self.items.into_iter().zip(blind_sigs.iter()) {
            let msg = token_input(&nonce, &self.challenge_digest, &self.token_key_id);
            let sig = self
                .derived_pk
                .finalize(bs, &br, &msg, Some(&meta))
                .map_err(Error::from)?;
            out.push(PbToken {
                policy: self.policy.clone(),
                nonce,
                challenge_digest: self.challenge_digest,
                token_key_id: self.token_key_id,
                authenticator: sig,
            });
        }
        Ok(out)
    }
}

/// Origin-side verifier: derives the per-policy key from the master and checks
/// the token. The policy class is read from the token (public metadata).
pub struct PbVerifier {
    master: PbMasterPublicKey,
}

impl PbVerifier {
    pub fn new(master: PbMasterPublicKey) -> Self {
        Self { master }
    }

    /// Verify `token` for `challenge`, accepting only policies in `allowed`.
    /// Returns the spend nonce on success.
    pub fn verify(
        &self,
        token: &PbToken,
        challenge: &TokenChallenge,
        allowed: &[PolicyClass],
    ) -> Result<[u8; 32], Error> {
        if !allowed.contains(&token.policy) {
            return Err(Error::Malformed(format!(
                "policy class {:?} not accepted by this origin",
                token.policy.0
            )));
        }
        if token.challenge_digest != challenge.digest() {
            return Err(Error::ChallengeMismatch);
        }
        if token.token_key_id != self.master.token_key_id()? {
            return Err(Error::KeyIdMismatch);
        }
        let derived_pk = self
            .master
            .key
            .derive_public_key_for_metadata(token.policy.metadata())
            .map_err(Error::from)?;
        let msg = token_input(&token.nonce, &token.challenge_digest, &token.token_key_id);
        derived_pk
            .verify(
                &token.authenticator,
                None,
                &msg,
                Some(token.policy.metadata()),
            )
            .map_err(Error::from)?;
        Ok(token.nonce)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    // Partially-blind keygen needs *safe* primes, which are slow to find.
    // Use the smallest allowed modulus and generate exactly one issuer for the
    // whole module so CI stays fast (correctness is independent of key size).
    const TEST_BITS: usize = 1024;

    fn shared_issuer() -> &'static PbIssuer {
        static ISSUER: OnceLock<PbIssuer> = OnceLock::new();
        ISSUER.get_or_init(|| PbIssuer::generate(1, TEST_BITS).expect("pbrsa keygen"))
    }

    fn challenge() -> TokenChallenge {
        TokenChallenge::new("issuer.example", "origin.example")
    }

    #[test]
    fn pbrsa_roundtrip_under_policy() {
        let issuer = shared_issuer();
        let master = issuer.master_public();
        let policy = PolicyClass::new("accepted-builds-v1");
        let ch = challenge();

        let (blinded, pending) = PbClient::begin(&master, &policy, &ch, 2).unwrap();
        let sigs = issuer.blind_sign(&blinded, &policy).unwrap();
        let tokens = pending.finalize(&sigs).unwrap();
        assert_eq!(tokens.len(), 2);

        let verifier = PbVerifier::new(master);
        for t in &tokens {
            let nonce = verifier
                .verify(t, &ch, std::slice::from_ref(&policy))
                .unwrap();
            assert_eq!(nonce, t.nonce);
        }
    }

    #[test]
    fn wrong_policy_key_does_not_verify() {
        // A token issued under policy A must not verify under policy B's key:
        // the metadata is bound into the signature.
        let issuer = shared_issuer();
        let master = issuer.master_public();
        let policy_a = PolicyClass::new("class-a");
        let ch = challenge();

        let (blinded, pending) = PbClient::begin(&master, &policy_a, &ch, 1).unwrap();
        let sigs = issuer.blind_sign(&blinded, &policy_a).unwrap();
        let mut token = pending.finalize(&sigs).unwrap().pop().unwrap();
        // Relabel the token to a different class and try to redeem.
        token.policy = PolicyClass::new("class-b");

        let verifier = PbVerifier::new(master);
        assert!(verifier
            .verify(&token, &ch, &[PolicyClass::new("class-b")])
            .is_err());
    }

    #[test]
    fn issuer_signing_wrong_policy_fails_finalize() {
        // If the issuer signs under a different policy than the client blinded
        // for, finalize (which verifies) must fail — no silent cross-class.
        let issuer = shared_issuer();
        let master = issuer.master_public();
        let ch = challenge();

        let (blinded, pending) =
            PbClient::begin(&master, &PolicyClass::new("class-a"), &ch, 1).unwrap();
        let sigs = issuer
            .blind_sign(&blinded, &PolicyClass::new("class-b"))
            .unwrap();
        assert!(pending.finalize(&sigs).is_err());
    }

    #[test]
    fn origin_rejects_unlisted_policy() {
        let issuer = shared_issuer();
        let master = issuer.master_public();
        let policy = PolicyClass::new("class-a");
        let ch = challenge();
        let (blinded, pending) = PbClient::begin(&master, &policy, &ch, 1).unwrap();
        let sigs = issuer.blind_sign(&blinded, &policy).unwrap();
        let token = pending.finalize(&sigs).unwrap().pop().unwrap();

        let verifier = PbVerifier::new(master);
        // origin only accepts a different class
        assert!(verifier
            .verify(&token, &ch, &[PolicyClass::new("other")])
            .is_err());
    }
}
