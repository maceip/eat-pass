//! eat-pass — attestation-gated, unlinkable authorization tokens.
//!
//! Roles (split attester / issuer trust boundary):
//! - `attester`  verify hardware attestation → signed issuance authorization
//! - `issuer`    blind-sign only on valid authorization (RSA key only)
//! - `token`     client mint path (attester → issuer)
//! - `origin`    example resource server
//! - `redeem`    central double-spend authority

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eat_pass_cli::tls::TlsPaths;
use eat_pass_cli::{attester, client, issuer, origin, redeemer};

#[derive(Parser)]
#[command(
    name = "eat-pass",
    version,
    about = "attestation-gated, unlinkable authorization tokens"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone, Default)]
struct ServeTls {
    /// PEM certificate for HTTPS (required on non-loopback binds).
    #[arg(long, value_name = "PEM")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for HTTPS (required on non-loopback binds).
    #[arg(long, value_name = "PEM")]
    tls_key: Option<PathBuf>,
    /// Allow plain HTTP on loopback only (local dev; never use on routable interfaces).
    #[arg(long)]
    insecure_http: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Verify attestation and issue short-lived authorization tokens.
    Attester {
        #[command(flatten)]
        tls: ServeTls,
        #[arg(long, default_value = "127.0.0.1:8087")]
        listen: SocketAddr,
        #[arg(long)]
        gate: String,
        #[arg(long = "allow", value_name = "HEX")]
        allow: Vec<String>,
        #[arg(long, default_value = "default")]
        class: String,
        #[arg(long, default_value_t = 1)]
        class_version: u32,
        /// Authorization lifetime in seconds.
        #[arg(long, default_value_t = 60)]
        auth_ttl_secs: u64,
    },

    /// Blind-signing issuer (RSA key only; requires attester-signed authorization).
    Issuer {
        #[command(flatten)]
        tls: ServeTls,
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: SocketAddr,
        /// Attester ed25519 verifying key (64 hex chars). Issuer trusts only
        /// authorization signatures from this key.
        #[arg(long)]
        attester_pub: String,
        #[arg(long, default_value_t = 3072)]
        modulus_bits: usize,
        #[arg(long, default_value_t = 100)]
        max_per_epoch: u32,
        #[arg(long, default_value_t = 3600)]
        epoch_secs: u64,
        #[arg(long, value_name = "URL")]
        rate_backend: Option<String>,
    },

    /// Client: mint tokens via attester → issuer.
    Token {
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        issuer: String,
        #[arg(long, default_value = "http://127.0.0.1:8087")]
        attester: String,
        #[arg(
            long,
            default_value = "sudo /home/azureuser/unified-quote/target/release/uq azure collect"
        )]
        uq_collect: String,
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long, default_value = "issuer.eat-pass.dev")]
        issuer_name: String,
        #[arg(long, default_value = "origin.eat-pass.dev")]
        origin_info: String,
        #[arg(long, value_name = "URL")]
        present: Option<String>,
        #[arg(long)]
        kt_log_pub: String,
        #[arg(long)]
        kt_known_head: Option<String>,
        /// Accept self-signed TLS certs (dev only).
        #[arg(long)]
        insecure_tls: bool,
    },

    VerifyEat {
        #[arg(long)]
        eat: String,
        #[arg(long)]
        binding: String,
    },

    VerifyAzure {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        binding: String,
    },

    VerifyAzureTls {
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        binding: String,
    },

    Origin {
        #[command(flatten)]
        tls: ServeTls,
        #[arg(long, default_value = "127.0.0.1:8099")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        issuer: String,
        #[arg(long, default_value = "issuer.eat-pass.dev")]
        issuer_name: String,
        #[arg(long, default_value = "origin.eat-pass.dev")]
        origin_info: String,
        #[arg(long, value_name = "URL")]
        redeemer: String,
        #[arg(long)]
        kt_log_pub: String,
        #[arg(long)]
        insecure_tls: bool,
    },

    Redeem {
        #[command(flatten)]
        tls: ServeTls,
        #[arg(long, default_value = "127.0.0.1:8100")]
        listen: SocketAddr,
        #[arg(long, value_name = "URL")]
        backend: Option<String>,
        #[arg(long, default_value_t = 86_400)]
        ttl_secs: u64,
    },
}

fn parse_hex32(s: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).map_err(|e| anyhow::anyhow!("{what}: bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what}: expected 32 bytes (64 hex chars)"))
}

fn parse_known_head(s: &str) -> anyhow::Result<eat_pass_core::transparency::SignedHead> {
    let (seq, head) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("kt-known-head must be <seq>:<head-hex>"))?;
    let seq: u64 = seq
        .parse()
        .map_err(|e| anyhow::anyhow!("kt-known-head seq: {e}"))?;
    let _ = parse_hex32(head, "kt-known-head head")?;
    Ok(eat_pass_core::transparency::SignedHead {
        seq,
        head: head.trim().to_string(),
        sig: String::new(),
    })
}

fn parse_gate(gate: &str) -> anyhow::Result<issuer::Backend> {
    match gate {
        "uq" => Ok(issuer::Backend::Uq),
        "azure" => Ok(issuer::Backend::Azure),
        "azure-tls" => Ok(issuer::Backend::AzureTls),
        other => anyhow::bail!(
            "unknown --gate '{other}' (expected 'uq', 'azure', or 'azure-tls')"
        ),
    }
}

fn parse_allow(allow: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    let decoded = allow
        .iter()
        .map(|h| hex::decode(h.trim()).map_err(|e| anyhow::anyhow!("allow: bad hex: {e}")))
        .collect::<anyhow::Result<Vec<_>>>()?;
    if decoded.is_empty() {
        anyhow::bail!("needs at least one --allow <value_x hex>");
    }
    Ok(decoded)
}

fn tls_paths(tls: &ServeTls) -> anyhow::Result<Option<TlsPaths>> {
    match (&tls.tls_cert, &tls.tls_key) {
        (Some(cert), Some(key)) => Ok(Some(TlsPaths {
            cert_pem: cert.clone(),
            key_pem: key.clone(),
        })),
        (None, None) => Ok(None),
        _ => anyhow::bail!("--tls-cert and --tls-key must be set together"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Attester {
            tls,
            listen,
            gate,
            allow,
            class,
            class_version,
            auth_ttl_secs,
        } => {
            attester::run(
                listen,
                parse_gate(&gate)?,
                parse_allow(&allow)?,
                class,
                class_version,
                auth_ttl_secs,
                tls_paths(&tls)?,
                tls.insecure_http,
            )
            .await?;
        }

        Cmd::Issuer {
            tls,
            listen,
            attester_pub,
            modulus_bits,
            max_per_epoch,
            epoch_secs,
            rate_backend,
        } => {
            issuer::run(
                listen,
                attester_pub,
                modulus_bits,
                max_per_epoch,
                epoch_secs,
                rate_backend,
                tls_paths(&tls)?,
                tls.insecure_http,
            )
            .await?;
        }

        Cmd::Token {
            issuer,
            attester,
            uq_collect,
            count,
            issuer_name,
            origin_info,
            present,
            kt_log_pub,
            kt_known_head,
            insecure_tls,
        } => {
            let attest = client::Attest::Azure { cmd: uq_collect };
            client::run(
                issuer,
                attester,
                attest,
                count,
                issuer_name,
                origin_info,
                present,
                parse_hex32(&kt_log_pub, "kt-log-pub")?,
                kt_known_head.map(|s| parse_known_head(&s)).transpose()?,
                insecure_tls,
            )
            .await?;
        }

        Cmd::VerifyEat { eat, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let eat = hex::decode(eat.trim()).map_err(|e| anyhow::anyhow!("eat: bad hex: {e}"))?;
            let binding = parse_hex32(&binding, "binding")?;
            match eat_pass_gate::UqVerifier::new().verify(&eat, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform   {}", m.platform);
                    println!("value_x    {}", hex::encode(&m.value_x));
                    println!("binding    {} (== eat_nonce)", hex::encode(binding));
                }
                Err(e) => anyhow::bail!("INVALID: {e}"),
            }
        }

        Cmd::VerifyAzure { bundle, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let json = std::fs::read(&bundle)
                .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle.display()))?;
            let binding = parse_hex32(&binding, "binding")?;
            match eat_pass_gate::AzureUqVerifier::new().verify(&json, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform     {}", m.platform);
                    println!("measurement  {}", hex::encode(&m.value_x));
                    println!(
                        "value_x      {} (== AK-quoted qualifyingData)",
                        hex::encode(binding)
                    );
                }
                Err(e) => anyhow::bail!("INVALID: {e}"),
            }
        }

        Cmd::VerifyAzureTls { cert, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let der = std::fs::read(&cert)
                .map_err(|e| anyhow::anyhow!("read cert {}: {e}", cert.display()))?;
            let binding = parse_hex32(&binding, "binding")?;
            match eat_pass_gate::AzureTlsVerifier::new().verify(&der, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform     {}", m.platform);
                    println!("measurement  {}", hex::encode(&m.value_x));
                    println!(
                        "value_x      {} (== bound qualifyingData)",
                        hex::encode(binding)
                    );
                }
                Err(e) => anyhow::bail!("INVALID: {e}"),
            }
        }

        Cmd::Origin {
            tls,
            listen,
            issuer,
            issuer_name,
            origin_info,
            redeemer,
            kt_log_pub,
            insecure_tls,
        } => {
            origin::run(
                listen,
                issuer,
                issuer_name,
                origin_info,
                redeemer,
                parse_hex32(&kt_log_pub, "kt-log-pub")?,
                tls_paths(&tls)?,
                tls.insecure_http,
                insecure_tls,
            )
            .await?;
        }

        Cmd::Redeem {
            tls,
            listen,
            backend,
            ttl_secs,
        } => {
            redeemer::run(
                listen,
                backend,
                ttl_secs,
                tls_paths(&tls)?,
                tls.insecure_http,
            )
            .await?;
        }
    }
    Ok(())
}
