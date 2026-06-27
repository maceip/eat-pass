//! `eat-pass demo` — split attester/issuer flow in one process (dev-sim only).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::authorize::{attester_pubkey_from_hex, issue_authorized_with_limit, dev};
use eat_pass_core::gate::Measurement;
use eat_pass_core::ratelimit::InMemoryRateLimiter;
use eat_pass_core::spend::{InMemorySpentStore, SpendError, SpentStore};
use eat_pass_core::{http, Client, Issuer, SignResponse, TokenChallenge};

use crate::wire::SignBody;

/// Run the end-to-end split attester → issuer flow.
pub fn run_in_process(modulus_bits: usize, count: usize) -> anyhow::Result<usize> {
    let seed = [0x42u8; 32];
    let value_x = vec![0x42u8; 32];
    let measurement = Measurement::new("dev", value_x.clone());

    let (attester, authorizer) = dev::from_seed(seed, [value_x.clone()])
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let attester_pub =
        attester_pubkey_from_hex(&hex::encode(authorizer.verifying_key())).unwrap();

    let issuer = Issuer::generate(1, modulus_bits)?;
    let pk = issuer.public();
    let limiter = InMemoryRateLimiter::new(64, 3600);

    let challenge = TokenChallenge::new("issuer.eat-pass.dev", "origin.eat-pass.dev");
    let origin_verifier = eat_pass_core::Verifier::new(pk.clone());
    let spent = InMemorySpentStore::new();

    println!(
        "setup    attester vk={}",
        hex::encode(authorizer.verifying_key())
    );
    println!(
        "         issuer   v{} token_key_id={}",
        pk.key_version,
        hex::encode(pk.token_key_id()?)
    );

    let (req, pending) =
        Client::begin(&pk, &challenge, count).map_err(|e| anyhow::anyhow!("begin: {e}"))?;
    let binding = req.binding();
    let eat = attester.attest(&measurement, &binding);
    let now = 1_700_000_000u64;
    let auth = authorizer
        .authorize(&eat, &binding, count as u32, now)
        .map_err(|e| anyhow::anyhow!("authorize: {e}"))?;

    let body: SignBody = serde_json::from_str(&serde_json::to_string(&SignBody {
        req,
        authorization_b64: B64.encode(serde_json::to_vec(&auth)?),
    })?)?;
    let auth: eat_pass_core::authorize::IssuanceAuthorization =
        serde_json::from_slice(&B64.decode(body.authorization_b64.as_bytes())?)?;

    let resp = issue_authorized_with_limit(
        &issuer,
        &attester_pub,
        &body.req,
        &auth,
        &limiter,
        now,
    )
    .map_err(|e| anyhow::anyhow!("issuer rejected: {e}"))?;
    let resp: SignResponse = serde_json::from_str(&serde_json::to_string(&resp)?)?;

    let tokens = pending
        .finalize(&pk, &resp)
        .map_err(|e| anyhow::anyhow!("finalize: {e}"))?;

    let first = tokens.first().ok_or_else(|| anyhow::anyhow!("no tokens"))?;
    let auth_hdr = http::authorization(first);
    let presented = http::parse_authorization(&auth_hdr).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let nonce = origin_verifier
        .verify(&presented, &challenge)
        .map_err(|e| anyhow::anyhow!("verify: {e}"))?;
    spent.check_and_mark(pk.key_version, &nonce)?;

    match spent.check_and_mark(pk.key_version, &nonce) {
        Err(SpendError::DoubleSpend) => {}
        Err(SpendError::Backend(e)) => anyhow::bail!("spend backend error: {e}"),
        Ok(()) => anyhow::bail!("double-spend was not detected"),
    }

    Ok(tokens.len())
}
