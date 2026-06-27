//! eat-pass — attestation-gated, unlinkable authorization tokens.
//!
//! One binary, four roles:
//! - `demo`          run the whole flow in-process (no network).
//! - `attester-key`  generate a dev attester identity (seed + verifying key).
//! - `issuer`        serve `GET /keys` + gated `POST /sign`.
//! - `token`         client: mint tokens against an issuer (and optionally spend one).
//! - `origin`        example resource server gated on a `PrivateToken`.
//!
//! The credential is an RFC 9474 blind-RSA signature in the RFC 9578 token type
//! `0x0002` format; issuance is gated on attestation (a unified-quote eat in
//! production, a dev ed25519 statement here). See `eat-pass-core`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eat_pass_cli::{client, demo, issuer, origin, redeemer};

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

#[derive(Subcommand)]
enum Cmd {
    /// Run issuer→client→origin end-to-end in one process (no network).
    Demo {
        /// RSA modulus bits for the demo issuer key (small = fast).
        #[arg(long, default_value_t = 2048)]
        modulus_bits: usize,
        /// Number of tokens to mint in the batch.
        #[arg(long, default_value_t = 3)]
        count: usize,
    },

    /// Generate a dev attester identity: prints `seed` (give to `token`) and
    /// `verifying-key` (give to `issuer --attester-key`).
    AttesterKey,

    /// Serve the issuance API: `GET /keys`, gated `POST /sign`.
    Issuer {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: SocketAddr,
        /// Attestation backend: `dev` (ed25519 dev statements), `uq`
        /// (unified-quote CBOR EAT), `azure` (SEV-SNP vTPM bundle), or
        /// `azure-tls` (attested-TLS leaf cert, the live Azure node's shape).
        #[arg(long, default_value = "dev")]
        gate: String,
        /// Trusted dev attester verifying key (64 hex chars). Required for
        /// `--gate dev`; ignored for `--gate uq`.
        #[arg(long)]
        attester_key: Option<String>,
        /// An accepted measurement `value_x` (hex). Repeatable.
        #[arg(long = "allow", value_name = "HEX")]
        allow: Vec<String>,
        /// Name of the accepted measurement class (anonymity set).
        #[arg(long, default_value = "default")]
        class: String,
        /// Version of the measurement class.
        #[arg(long, default_value_t = 1)]
        class_version: u32,
        /// RSA modulus bits for the issuance key.
        #[arg(long, default_value_t = 2048)]
        modulus_bits: usize,
        /// Max tokens issued per attested build per epoch.
        #[arg(long, default_value_t = 100)]
        max_per_epoch: u32,
        /// Rate-limit epoch length in seconds.
        #[arg(long, default_value_t = 3600)]
        epoch_secs: u64,
    },

    /// Client: mint tokens against a running issuer.
    Token {
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        issuer: String,
        /// Dev attester seed (64 hex chars) from `attester-key`.
        #[arg(long)]
        attester_seed: String,
        /// Platform label for the attestation.
        #[arg(long, default_value = "dev")]
        platform: String,
        /// The build measurement `value_x` (hex) — must be in the issuer's class.
        #[arg(long)]
        value_x: String,
        /// Number of tokens to mint in this batch.
        #[arg(long, default_value_t = 1)]
        count: usize,
        /// Issuer name in the token challenge (must match the origin).
        #[arg(long, default_value = "issuer.eat-pass.dev")]
        issuer_name: String,
        /// Origin info in the token challenge (must match the origin).
        #[arg(long, default_value = "origin.eat-pass.dev")]
        origin_info: String,
        /// If set, immediately present the first token to this origin URL.
        #[arg(long, value_name = "URL")]
        present: Option<String>,
        /// Pin the issuer's key-transparency log public key (64 hex chars). When
        /// set, the client fetches `/kt` and refuses to use an issuer key that
        /// is not committed in the signed log.
        #[arg(long)]
        kt_log_pub: Option<String>,
    },

    /// Verify a unified-quote EAT through the real gate (`UqVerifier`) and print
    /// the extracted measurement. The eat is the hex of its CBOR bytes; the
    /// binding is the 32-byte channel binding the eat's `eat_nonce` must equal.
    VerifyEat {
        /// EAT CBOR bytes, hex-encoded (e.g. from `uq build`/`uq run` output).
        #[arg(long)]
        eat: String,
        /// Expected channel binding (64 hex chars) = the eat's eat_nonce.
        #[arg(long)]
        binding: String,
    },

    /// Verify a live Azure attested-TLS leaf certificate through the real gate
    /// (`AzureTlsVerifier`) and print the SNP launch measurement. The cert is a
    /// DER file (e.g. captured from `attest.secure.build:8443`); binding is the
    /// 32-byte value_x the AK quote committed.
    VerifyAzureTls {
        /// Path to the DER-encoded TLS leaf certificate.
        #[arg(long)]
        cert: PathBuf,
        /// Expected bound value_x (64 hex chars).
        #[arg(long)]
        binding: String,
    },

    /// Example origin: gate `GET /resource` on a `PrivateToken`.
    Origin {
        #[arg(long, default_value = "127.0.0.1:8099")]
        listen: SocketAddr,
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        issuer: String,
        /// Issuer name in the token challenge (must match the client).
        #[arg(long, default_value = "issuer.eat-pass.dev")]
        issuer_name: String,
        /// Origin info in the token challenge (must match the client).
        #[arg(long, default_value = "origin.eat-pass.dev")]
        origin_info: String,
        /// Central redeemer URL for shared double-spend across replicas. If
        /// unset, double-spend is tracked origin-locally.
        #[arg(long, value_name = "URL")]
        redeemer: Option<String>,
    },

    /// Central double-spend authority: `POST /redeem` shared by origin replicas.
    Redeem {
        #[arg(long, default_value = "127.0.0.1:8100")]
        listen: SocketAddr,
    },
}

fn parse_hex32(s: &str, what: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s.trim()).map_err(|e| anyhow::anyhow!("{what}: bad hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what}: expected 32 bytes (64 hex chars)"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Demo {
            modulus_bits,
            count,
        } => {
            demo::run_in_process(modulus_bits, count)?;
        }

        Cmd::AttesterKey => {
            // A dev attester is fully determined by its 32-byte seed. The seed is
            // the private attester identity (treat it like a secret); the
            // verifying key is what an issuer pins via `--attester-key`.
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
            let vk = eat_pass_core::gate::DevAttester::from_seed(seed).verifying_key();
            println!("seed          {}", hex::encode(seed));
            println!("verifying-key {}", hex::encode(vk));
        }

        Cmd::Issuer {
            listen,
            gate,
            attester_key,
            allow,
            class,
            class_version,
            modulus_bits,
            max_per_epoch,
            epoch_secs,
        } => {
            let backend = match gate.as_str() {
                "dev" => {
                    let key = attester_key
                        .ok_or_else(|| anyhow::anyhow!("--gate dev requires --attester-key"))?;
                    issuer::Backend::Dev {
                        attester_key: parse_hex32(&key, "attester-key")?,
                    }
                }
                "uq" => issuer::Backend::Uq,
                "azure" => issuer::Backend::Azure,
                "azure-tls" => issuer::Backend::AzureTls,
                other => anyhow::bail!(
                    "unknown --gate '{other}' (expected 'dev', 'uq', 'azure', or 'azure-tls')"
                ),
            };
            let allow = allow
                .iter()
                .map(|h| hex::decode(h.trim()).map_err(|e| anyhow::anyhow!("allow: bad hex: {e}")))
                .collect::<anyhow::Result<Vec<_>>>()?;
            if allow.is_empty() {
                anyhow::bail!("issuer needs at least one --allow <value_x hex>");
            }
            issuer::run(
                listen,
                backend,
                allow,
                class,
                class_version,
                modulus_bits,
                max_per_epoch,
                epoch_secs,
            )
            .await?;
        }

        Cmd::Token {
            issuer,
            attester_seed,
            platform,
            value_x,
            count,
            issuer_name,
            origin_info,
            present,
            kt_log_pub,
        } => {
            let attester_seed = parse_hex32(&attester_seed, "attester-seed")?;
            let value_x = hex::decode(value_x.trim())
                .map_err(|e| anyhow::anyhow!("value-x: bad hex: {e}"))?;
            let kt_log_pub = kt_log_pub
                .map(|h| parse_hex32(&h, "kt-log-pub"))
                .transpose()?;
            client::run(
                issuer,
                attester_seed,
                platform,
                value_x,
                count,
                issuer_name,
                origin_info,
                present,
                kt_log_pub,
            )
            .await?;
        }

        Cmd::VerifyEat { eat, binding } => {
            use eat_pass_core::gate::AttestationVerifier;
            let eat = hex::decode(eat.trim()).map_err(|e| anyhow::anyhow!("eat: bad hex: {e}"))?;
            let binding = parse_hex32(&binding, "binding")?;
            let verifier = eat_pass_gate::UqVerifier::new();
            match verifier.verify(&eat, &binding) {
                Ok(m) => {
                    println!("VALID");
                    println!("platform   {}", m.platform);
                    println!("value_x    {}", hex::encode(&m.value_x));
                    println!("binding    {} (== eat_nonce)", hex::encode(binding));
                }
                Err(e) => {
                    anyhow::bail!("INVALID: {e}");
                }
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
            listen,
            issuer,
            issuer_name,
            origin_info,
            redeemer,
        } => {
            origin::run(listen, issuer, issuer_name, origin_info, redeemer).await?;
        }

        Cmd::Redeem { listen } => {
            redeemer::run(listen).await?;
        }
    }
    Ok(())
}
