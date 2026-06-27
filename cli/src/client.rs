//! `eat-pass token` — the client.
//!
//! Fetches the issuer key, blinds a batch of token inputs for a
//! [`TokenChallenge`], attaches a (dev) attestation over the request's channel
//! binding, calls `/sign`, finalizes the blind signatures into tokens, and
//! prints each token as an RFC 9577 `Authorization: PrivateToken` value. With
//! `--present` it immediately spends the first token against an origin.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::gate::{DevAttester, Measurement};
use eat_pass_core::{http, Client, IssuerPublicKey, SignResponse, TokenChallenge};

use crate::wire::SignBody;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    issuer_url: String,
    attester_seed: [u8; 32],
    platform: String,
    value_x: Vec<u8>,
    count: usize,
    issuer_name: String,
    origin_info: String,
    present: Option<String>,
) -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();

    // 1. fetch + pin the issuer key.
    let keys_url = format!("{}/keys", issuer_url.trim_end_matches('/'));
    let pk: IssuerPublicKey = http_client
        .get(&keys_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let tkid = pk.token_key_id()?;
    eprintln!(
        "issuer key  v{} token_key_id={}",
        pk.key_version,
        hex::encode(tkid)
    );

    // 2. blind `count` token inputs for this challenge.
    let challenge = TokenChallenge::new(issuer_name, origin_info);
    let (req, pending) =
        Client::begin(&pk, &challenge, count).map_err(|e| anyhow::anyhow!("begin: {e}"))?;

    // 3. attest over the request's channel binding (dev attester stands in for
    //    a TEE producing a unified-quote eat).
    let attester = DevAttester::from_seed(attester_seed);
    let measurement = Measurement::new(platform, value_x);
    let eat = attester.attest(&measurement, &req.binding());

    // 4. POST /sign — the issuer runs the gate, then blind-signs.
    let sign_url = format!("{}/sign", issuer_url.trim_end_matches('/'));
    let body = SignBody {
        req,
        eat_b64: B64.encode(eat),
    };
    let resp = http_client.post(&sign_url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("issuer rejected /sign ({status}): {text}");
    }
    let sign_resp: SignResponse = resp.json().await?;

    // 5. finalize into unlinkable tokens.
    let tokens = pending
        .finalize(&pk, &sign_resp)
        .map_err(|e| anyhow::anyhow!("finalize: {e}"))?;
    eprintln!("minted {} token(s):", tokens.len());
    for t in &tokens {
        println!("{}", http::authorization(t));
    }

    // 6. optionally spend the first token against an origin.
    if let Some(resource_url) = present {
        let first = tokens.first().ok_or_else(|| anyhow::anyhow!("no tokens"))?;
        let r = http_client
            .get(&resource_url)
            .header("authorization", http::authorization(first))
            .send()
            .await?;
        let status = r.status();
        let text = r.text().await.unwrap_or_default();
        eprintln!("present → {resource_url}: {status}");
        println!("{text}");
    }
    Ok(())
}
