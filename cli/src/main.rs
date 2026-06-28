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
use eat_pass_cli::{attester, client, issuer, origin, policy, redeemer};

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
        #[arg(long, value_name = "FILE")]
        policy: PathBuf,
        /// Authorization lifetime in seconds.
        #[arg(long, default_value_t = 60)]
        auth_ttl_secs: u64,
    },

    /// Blind-signing issuer (PoMFRIT key only; requires attester-signed authorization).
    Issuer {
        #[command(flatten)]
        tls: ServeTls,
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: SocketAddr,
        /// Attester FAEST-128f verifying key (64 hex chars). Issuer trusts only
        /// authorization signatures from this key.
        #[arg(long)]
        attester_pub: String,
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
        /// Attestation collector: `azure` (default), `desktop-tpm`, or `desktop-bundle`.
        #[arg(long, default_value = "azure")]
        attest_mode: String,
        #[arg(
            long,
            default_value = "sudo /home/azureuser/unified-quote/target/release/uq azure collect"
        )]
        uq_collect: String,
        #[arg(long, default_value = "scripts/collect-desktop-tpm.sh")]
        desktop_collect: String,
        /// sha256(agent binary) hex — required for `desktop-tpm` mode.
        #[arg(long)]
        build_digest: Option<String>,
        /// Pre-collected desktop evidence JSON — required for `desktop-bundle` mode.
        #[arg(long, value_name = "FILE")]
        desktop_bundle: Option<PathBuf>,
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

    VerifyDesktopTpm {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        binding: String,
    },

    VerifyMacOsAppAttest {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        binding: String,
    },

    /// Compute desktop policy `measurement` from agent binary sha256.
    DesktopHashBuild {
        #[arg(value_name = "FILE")]
        path: PathBuf,
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
        /// Require a 32-byte redemption context on every issued challenge (Hanff CCS 2025).
        #[arg(long, default_value_t = true)]
        require_redemption_context: bool,
        /// Allow empty redemption context (local testing only).
        #[arg(long, conflicts_with = "require_redemption_context")]
        allow_empty_redemption_context: bool,
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

    /// Operator verification policy (reference values, validity, registry floor).
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Parse and structurally validate a policy JSON file.
    Validate {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Appraise normalized claims (post crypto-verify) against a policy file.
    Simulate {
        #[arg(long, value_name = "FILE")]
        policy: PathBuf,
        #[arg(long, value_name = "FILE")]
        claims: PathBuf,
    },
    /// Compare two policy files (Verdict-style operator diff).
    Diff {
        #[arg(long, value_name = "FILE")]
        left: PathBuf,
        #[arg(long, value_name = "FILE")]
        right: PathBuf,
    },
    /// Sign a policy JSON file (writes `<file>.sig`; needs EATPASS_POLICY_SIGNING_SEED).
    Sign {
        #[arg(long, value_name = "FILE")]
        file: PathBuf,
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
        "android-key" | "android" => Ok(issuer::Backend::AndroidKey),
        "ios-app-attest" | "ios" => Ok(issuer::Backend::IosAppAttest),
        "desktop-tpm" | "linux-tpm" | "windows-tpm" => Ok(issuer::Backend::DesktopTpm),
        "macos-app-attest" | "macos" => Ok(issuer::Backend::MacOsAppAttest),
        other => anyhow::bail!(
            "unknown --gate '{other}' (expected uq, azure, azure-tls, android-key, ios-app-attest, desktop-tpm, macos-app-attest)"
        ),
    }
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
            policy,
            auth_ttl_secs,
        } => {
            attester::run(
                listen,
                parse_gate(&gate)?,
                policy,
                &gate,
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
            max_per_epoch,
            epoch_secs,
            rate_backend,
        } => {
            issuer::run(
                listen,
                attester_pub,
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
            attest_mode,
            uq_collect,
            desktop_collect,
            build_digest,
            desktop_bundle,
            count,
            issuer_name,
            origin_info,
            present,
            kt_log_pub,
            kt_known_head,
            insecure_tls,
        } => {
            let attest = match attest_mode.as_str() {
                "azure" => client::Attest::Azure { cmd: uq_collect },
                "desktop-tpm" => client::Attest::DesktopTpm {
                    script: desktop_collect,
                    build_digest: build_digest.ok_or_else(|| {
                        anyhow::anyhow!("--build-digest required for desktop-tpm attest mode")
                    })?,
                },
                "desktop-bundle" => client::Attest::DesktopBundle {
                    path: desktop_bundle.ok_or_else(|| {
                        anyhow::anyhow!("--desktop-bundle required for desktop-bundle attest mode")
                    })?,
                },
                other => anyhow::bail!(
                    "unknown --attest-mode '{other}' (expected azure, desktop-tpm, desktop-bundle)"
                ),
            };
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

        Cmd::VerifyDesktopTpm { bundle, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let json = std::fs::read(&bundle)
                .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle.display()))?;
            let binding = parse_hex32(&binding, "binding")?;
            match eat_pass_gate::DesktopTpmVerifier::new().verify(&json, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform   {}", m.platform);
                    println!("value_x    {}", hex::encode(&m.value_x));
                }
                Err(e) => anyhow::bail!("INVALID: {e}"),
            }
        }

        Cmd::VerifyMacOsAppAttest { bundle, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let json = std::fs::read(&bundle)
                .map_err(|e| anyhow::anyhow!("read bundle {}: {e}", bundle.display()))?;
            let binding = parse_hex32(&binding, "binding")?;
            match eat_pass_gate::MacOsAppAttestVerifier::new().verify(&json, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform   {}", m.platform);
                    println!("value_x    {}", hex::encode(&m.value_x));
                }
                Err(e) => anyhow::bail!("INVALID: {e}"),
            }
        }

        Cmd::DesktopHashBuild { path } => {
            use sha2::{Digest, Sha256};
            use std::io::Read;
            let mut f = std::fs::File::open(&path)
                .map_err(|e| anyhow::anyhow!("open {}: {e}", path.display()))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let digest: [u8; 32] = Sha256::digest(&buf).into();
            let id = unified_quote::tee::desktop::desktop_build_id_hash(&digest);
            println!("build_digest   {}", hex::encode(digest));
            println!("build_id_hash  {}", hex::encode(id));
            println!("policy allow.measurement = build_id_hash");
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
            require_redemption_context,
            allow_empty_redemption_context,
        } => {
            let require_ctx = require_redemption_context && !allow_empty_redemption_context;
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
                require_ctx,
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

        Cmd::Policy { cmd } => match cmd {
            PolicyCmd::Validate { file } => policy::validate(&file)?,
            PolicyCmd::Simulate { policy, claims } => policy::simulate(&policy, &claims)?,
            PolicyCmd::Diff { left, right } => policy::diff_policies(&left, &right)?,
            PolicyCmd::Sign { file } => policy::sign(&file)?,
        },
    }
    Ok(())
}
