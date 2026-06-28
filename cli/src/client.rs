//! `eat-pass token` — the client.
//!
//! Fetches the issuer key, blinds token inputs, obtains an attester-signed
//! authorization over the channel binding, calls `/sign`, finalizes tokens.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use eat_pass_core::transparency::{verify_consistency, verify_inclusion, verify_log, SignedHead};
use eat_pass_core::{http, Client, IssuerPublicKey, SignResponse, TokenChallenge};

use crate::wire::{AuthorizeBody, AuthorizeResponse, KtResponse, SignBody};

/// How the client produces attestation evidence bound to the channel binding.
pub enum Attest {
    /// Real Azure SEV-SNP vTPM bundle via `uq azure collect --value-x <binding>`.
    Azure { cmd: String },
    /// Linux/Windows TPM2 via `scripts/collect-desktop-tpm.sh`.
    DesktopTpm {
        script: String,
        build_digest: String,
    },
    /// Pre-collected desktop evidence JSON (TPM bundle or macOS App Attest).
    DesktopBundle { path: std::path::PathBuf },
}

fn collect_eat(attest: &Attest, binding: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    match attest {
        Attest::Azure { cmd } => {
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
        Attest::DesktopTpm { script, build_digest } => {
            let out = tempfile_path("eatpass-desktop-tpm", "json")?;
            let binding_hex = hex::encode(binding);
            let status = std::process::Command::new("bash")
                .arg(script)
                .arg("-o")
                .arg(&out)
                .env("BINDING", &binding_hex)
                .env("BUILD_DIGEST", build_digest)
                .status()
                .map_err(|e| anyhow::anyhow!("spawn desktop tpm collect `{script}`: {e}"))?;
            if !status.success() {
                anyhow::bail!("desktop tpm collect exited with {status}");
            }
            std::fs::read(&out).map_err(|e| anyhow::anyhow!("read {out}: {e}"))
        }
        Attest::DesktopBundle { path } => std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("read desktop bundle {}: {e}", path.display())),
    }
}

fn tempfile_path(prefix: &str, ext: &str) -> anyhow::Result<String> {
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let dir = std::env::temp_dir();
    Ok(dir
        .join(format!("{prefix}-{}.{ext}", hex::encode(rnd)))
        .to_string_lossy()
        .into_owned())
}

async fn fetch_origin_challenge(
    http: &reqwest::Client,
    resource_url: &str,
) -> anyhow::Result<TokenChallenge> {
    let r = http.get(resource_url).send().await?;
    if r.status() != reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!(
            "expected 401 from origin at {resource_url}, got {}",
            r.status()
        );
    }
    let hdr = r
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            anyhow::anyhow!("401 from {resource_url} missing WWW-Authenticate header")
        })?;
    http::parse_www_authenticate(hdr).map_err(|e| anyhow::anyhow!("parse challenge: {e}"))
}

fn http_client(insecure_tls: bool) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if insecure_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|e| anyhow::anyhow!("http client: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    issuer_url: String,
    attester_url: String,
    attest: Attest,
    count: usize,
    issuer_name: String,
    origin_info: String,
    present: Option<String>,
    kt_log_pub: [u8; 32],
    kt_known_head: Option<SignedHead>,
    insecure_tls: bool,
) -> anyhow::Result<()> {
    let http_client = http_client(insecure_tls)?;
    let issuer_base = issuer_url.trim_end_matches('/');
    let attester_base = attester_url.trim_end_matches('/');

    let keys_url = format!("{issuer_base}/keys");
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

    let log_pub = kt_log_pub;
    {
        let kt: KtResponse = http_client
            .get(format!("{issuer_base}/kt"))
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

        if let Some(old) = &kt_known_head {
            verify_consistency(old, &kt.records).map_err(|e| {
                anyhow::anyhow!("kt: new log is not consistent with the head you pinned: {e}")
            })?;
            eprintln!(
                "kt          OK — log is consistent with previously-seen head seq {}",
                old.seq
            );
        }

        eprintln!("kt-head     {}:{}", kt.signed_head.seq, kt.signed_head.head);
    }

    let challenge = if let Some(ref resource_url) = present {
        let ch = fetch_origin_challenge(&http_client, resource_url).await?;
        eprintln!(
            "origin      challenge digest={} redemption_context={}",
            hex::encode(ch.digest()),
            ch.has_redemption_context()
        );
        ch
    } else {
        TokenChallenge::new(issuer_name, origin_info)
    };
    let (req, pending) =
        Client::begin(&pk, &challenge, count).map_err(|e| anyhow::anyhow!("begin: {e}"))?;

    let binding = req.binding();
    let eat = collect_eat(&attest, &binding)?;

    let auth_body = AuthorizeBody {
        eat_b64: B64.encode(eat),
        binding: hex::encode(binding),
        max_batch: count as u32,
    };
    let auth_resp: AuthorizeResponse = http_client
        .post(format!("{attester_base}/authorize"))
        .json(&auth_body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    eprintln!("attester    authorization OK (binding={})", hex::encode(binding));

    let sign_url = format!("{issuer_base}/sign");
    let body = SignBody {
        req,
        authorization_b64: auth_resp.authorization_b64,
    };
    let resp = http_client.post(&sign_url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("issuer rejected /sign ({status}): {text}");
    }
    let sign_resp: SignResponse = resp.json().await?;

    let tokens = pending
        .finalize(&pk, &sign_resp)
        .map_err(|e| anyhow::anyhow!("finalize: {e}"))?;
    eprintln!("minted {} token(s):", tokens.len());
    for t in &tokens {
        println!("{}", http::authorization(t));
    }

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
