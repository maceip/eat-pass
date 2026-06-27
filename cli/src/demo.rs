//! `eat-pass demo` — the whole flow in one process, no network.
//!
//! Generates an attester, an issuer, a client, and an origin; mints a batch of
//! tokens gated on a (dev) attestation; verifies + spends one; and shows a
//! double-spend being rejected. This is the fastest way to see the protocol end
//! to end and is the basis of the integration test.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::gate::{issue_gated_with_limit, DevAttester, DevVerifier, Measurement};
use eat_pass_core::ratelimit::InMemoryRateLimiter;
use eat_pass_core::spend::{InMemorySpentStore, SpendError, SpentStore};
use eat_pass_core::{http, Client, Issuer, SignResponse, TokenChallenge};

use crate::wire::SignBody;

/// Run the end-to-end flow. `modulus_bits` is small in the demo/test for speed;
/// production issuers use 3072. Returns the number of tokens minted.
pub fn run_in_process(modulus_bits: usize, count: usize) -> anyhow::Result<usize> {
    // --- setup: attester (TEE stand-in), issuer, accepted build, origin ---
    let attester = DevAttester::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let value_x = vec![0x42u8; 32];
    let measurement = Measurement::new("dev", value_x.clone());

    let issuer = Issuer::generate(1, modulus_bits)?;
    let pk = issuer.public();
    let verifier_gate = DevVerifier::new(attester.verifying_key(), [value_x.clone()])
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let limiter = InMemoryRateLimiter::new(64, 3600);

    let challenge = TokenChallenge::new("issuer.eat-pass.dev", "origin.eat-pass.dev");
    let origin_verifier = eat_pass_core::Verifier::new(pk.clone());
    let spent = InMemorySpentStore::new();

    println!(
        "setup    attester vk={}",
        hex::encode(attester.verifying_key())
    );
    println!(
        "         issuer   v{} token_key_id={}",
        pk.key_version,
        hex::encode(pk.token_key_id()?)
    );
    println!("         build    value_x={}", hex::encode(&value_x));

    // --- client: blind a batch + attest over the channel binding ---
    let (req, pending) =
        Client::begin(&pk, &challenge, count).map_err(|e| anyhow::anyhow!("begin: {e}"))?;
    let eat = attester.attest(&measurement, &req.binding());
    println!(
        "client   blinded {count} token input(s); binding={}",
        hex::encode(req.binding())
    );

    // --- wire roundtrip the /sign body so the demo exercises the envelope ---
    let body = SignBody {
        req,
        eat_b64: B64.encode(&eat),
    };
    let body: SignBody = serde_json::from_str(&serde_json::to_string(&body)?)?;
    let eat = B64.decode(body.eat_b64.as_bytes())?;

    // --- issuer: gate (verify eat + binding + class + quota) then blind-sign ---
    let resp = issue_gated_with_limit(&issuer, &verifier_gate, &body.req, &eat, &limiter)
        .map_err(|e| anyhow::anyhow!("gate rejected: {e}"))?;
    let resp: SignResponse = serde_json::from_str(&serde_json::to_string(&resp)?)?;
    println!(
        "issuer   gate passed; blind-signed {} message(s)",
        resp.blind_sigs.len()
    );

    // --- client: finalize into unlinkable tokens ---
    let tokens = pending
        .finalize(&pk, &resp)
        .map_err(|e| anyhow::anyhow!("finalize: {e}"))?;
    println!("client   finalized {} token(s)", tokens.len());

    // --- origin: verify + spend the first token, then prove double-spend fails ---
    let first = tokens.first().ok_or_else(|| anyhow::anyhow!("no tokens"))?;
    let auth = http::authorization(first);
    let presented = http::parse_authorization(&auth).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    let nonce = origin_verifier
        .verify(&presented, &challenge)
        .map_err(|e| anyhow::anyhow!("verify: {e}"))?;
    spent
        .check_and_mark(pk.key_version, &nonce)
        .map_err(|e| anyhow::anyhow!("spend: {e}"))?;
    println!(
        "origin   token accepted + spent (nonce={})",
        hex::encode(nonce)
    );

    match spent.check_and_mark(pk.key_version, &nonce) {
        Err(SpendError::DoubleSpend) => {
            println!("origin   replay of the same token correctly rejected (double-spend)")
        }
        Err(SpendError::Backend(e)) => anyhow::bail!("spend backend error: {e}"),
        Ok(()) => anyhow::bail!("double-spend was not detected"),
    }

    println!(
        "ok       {} token(s) minted, 1 spent, replay blocked",
        tokens.len()
    );
    Ok(tokens.len())
}
