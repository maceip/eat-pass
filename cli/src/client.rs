//! `eat-pass token` — the client.
//!
//! Fetches the issuer key, blinds a batch of token inputs for a
//! [`TokenChallenge`], attaches a (dev) attestation over the request's channel
//! binding, calls `/sign`, finalizes the blind signatures into tokens, and
//! prints each token as an RFC 9577 `Authorization: PrivateToken` value. With
//! `--present` it immediately spends the first token against an origin.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::gate::{DevAttester, Measurement};
use eat_pass_core::transparency::{verify_consistency, verify_inclusion, verify_log, SignedHead};
use eat_pass_core::{http, Client, IssuerPublicKey, SignResponse, TokenChallenge};

use crate::wire::{KtResponse, SignBody};

/// How the client produces the attestation evidence (the `eat` bytes) that
/// commits to the request's channel binding.
pub enum Attest {
    /// Dev ed25519 statement over the channel binding (no hardware).
    Dev {
        seed: [u8; 32],
        platform: String,
        value_x: Vec<u8>,
    },
    /// Real Azure SEV-SNP vTPM bundle: shell out to `uq azure collect
    /// --value-x <channel-binding>` so the AK quote binds the binding. `cmd` is
    /// the collect invocation (argv joined by spaces), e.g.
    /// `sudo /home/azureuser/unified-quote/target/release/uq azure collect`.
    Azure { cmd: String },
}

/// Produce the `eat` bytes that bind `binding`, for the chosen attestation mode.
fn collect_eat(attest: &Attest, binding: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    match attest {
        Attest::Dev {
            seed,
            platform,
            value_x,
        } => {
            let attester = DevAttester::from_seed(*seed);
            let measurement = Measurement::new(platform.clone(), value_x.clone());
            Ok(attester.attest(&measurement, binding))
        }
        Attest::Azure { cmd } => {
            // `uq azure collect --value-x <hex(binding)> -o <tmp>` — the AK quote
            // commits hex(binding) as qualifyingData, which is exactly the
            // channel-binding tie AzureUqVerifier enforces. Needs vTPM access
            // (run with sudo on the CVM).
            let out = tempfile_path("eatpass-azure-bundle", "json")?;
            let mut argv = cmd.split_whitespace().collect::<Vec<_>>();
            if argv.is_empty() {
                anyhow::bail!("azure collect command is empty");
            }
            let prog = argv.remove(0);
            let binding_hex = hex::encode(binding);
            let status = std::process::Command::new(prog)
                .args(&argv)
                .args(["--value-x", &binding_hex, "-o", &out])
                .status()
                .map_err(|e| anyhow::anyhow!("spawn `{cmd}`: {e}"))?;
            if !status.success() {
                anyhow::bail!("`{cmd} --value-x {binding_hex}` exited with {status}");
            }
            let bytes = std::fs::read(&out)
                .map_err(|e| anyhow::anyhow!("read collected bundle {out}: {e}"))?;
            let _ = std::fs::remove_file(&out);
            Ok(bytes)
        }
    }
}

/// A unique scratch path under the system temp dir (no external tempfile dep).
fn tempfile_path(prefix: &str, ext: &str) -> anyhow::Result<String> {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let dir = std::env::temp_dir();
    Ok(dir
        .join(format!("{prefix}-{}.{ext}", hex::encode(rnd)))
        .to_string_lossy()
        .into_owned())
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    issuer_url: String,
    attest: Attest,
    count: usize,
    issuer_name: String,
    origin_info: String,
    present: Option<String>,
    kt_log_pub: Option<[u8; 32]>,
    kt_known_head: Option<SignedHead>,
) -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let base = issuer_url.trim_end_matches('/');

    // 1. fetch + pin the issuer key.
    let keys_url = format!("{base}/keys");
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

    // 1b. key transparency (E.4): if the caller pinned a log key, refuse to use
    //     an issuer key that is not committed in the issuer's published log.
    if let Some(log_pub) = kt_log_pub {
        let kt: KtResponse = http_client
            .get(format!("{base}/kt"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let served_pub = hex::decode(kt.log_pub.trim()).unwrap_or_default();
        if served_pub.as_slice() != log_pub {
            anyhow::bail!(
                "kt: issuer serves log pubkey {} but client pinned {}",
                kt.log_pub,
                hex::encode(log_pub)
            );
        }
        verify_log(&log_pub, &kt.records, &kt.signed_head)
            .map_err(|e| anyhow::anyhow!("kt: log does not verify against pinned key: {e}"))?;
        let seq = verify_inclusion(&kt.records, &tkid)
            .map_err(|e| anyhow::anyhow!("kt: issuer key not in transparency log: {e}"))?;
        eprintln!(
            "kt          OK — issuer key included at seq {seq}, log head signed by pinned key"
        );

        // Consistency across rotation (E.4): if the caller remembers an earlier
        // signed head, require that the current log *extends* it (the old head
        // must reappear mid-chain). This catches an issuer that rewrote history
        // to hide a key it briefly served.
        if let Some(old) = &kt_known_head {
            verify_consistency(old, &kt.records).map_err(|e| {
                anyhow::anyhow!("kt: new log is not consistent with the head you pinned: {e}")
            })?;
            eprintln!(
                "kt          OK — log is consistent with previously-seen head seq {}",
                old.seq
            );
        }

        // Emit the head we observed so a follow-up run (e.g. after a rotation)
        // can pin it via --kt-known-head and prove consistency.
        eprintln!("kt-head     {}:{}", kt.signed_head.seq, kt.signed_head.head);
    }

    // 2. blind `count` token inputs for this challenge.
    let challenge = TokenChallenge::new(issuer_name, origin_info);
    let (req, pending) =
        Client::begin(&pk, &challenge, count).map_err(|e| anyhow::anyhow!("begin: {e}"))?;

    // 3. attest over the request's channel binding. The dev attester stands in
    //    for a TEE; `Attest::Azure` collects a real SEV-SNP vTPM bundle whose AK
    //    quote binds this exact channel binding as qualifyingData.
    let binding = req.binding();
    let eat = collect_eat(&attest, &binding)?;

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
