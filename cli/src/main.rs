//! eat-pass — attestation-gated, unlinkable authorization tokens.
//!
//! One binary, the network roles:
//! - `issuer`        serve `GET /keys` + gated `POST /sign`.
//! - `token`         client: mint tokens against an issuer (and optionally spend one).
//! - `origin`        example resource server gated on a `PrivateToken`.
//! - `redeem`        central double-spend authority shared by origins.
//!
//! The credential is an RFC 9474 blind-RSA signature in the RFC 9578 token type
//! `0x0002` format. **Issuance is always gated on a real hardware attestation**
//! (a `unified-quote` EAT / Azure SEV-SNP bundle); there is no dev/insecure gate
//! and no flag to disable attestation or key-transparency. See `eat-pass-core`.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use eat_pass_cli::{client, issuer, origin, redeemer};

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
    /// Serve the issuance API: `GET /keys`, gated `POST /sign`.
    Issuer {
        #[arg(long, default_value = "127.0.0.1:8088")]
        listen: SocketAddr,
        /// Attestation backend (required): `uq` (unified-quote CBOR EAT),
        /// `azure` (SEV-SNP vTPM bundle), or `azure-tls` (attested-TLS leaf
        /// cert, the live Azure node's shape). Every option verifies a genuine
        /// hardware attestation to an AMD/Intel root — there is no dev gate.
        #[arg(long)]
        gate: String,
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
        /// Shared rate-limit backend URL (e.g. `redis://host:6379`) for a
        /// multi-replica issuer. Unset = process-local in-memory. Requires the
        /// `redis` build feature.
        #[arg(long, value_name = "URL")]
        rate_backend: Option<String>,
    },

    /// Client: mint tokens against a running issuer. Runs inside the attested
    /// CVM; collects a real SEV-SNP vTPM attestation bound to the request.
    Token {
        #[arg(long, default_value = "http://127.0.0.1:8088")]
        issuer: String,
        /// `uq azure collect` invocation (argv, joined by spaces). Collects a
        /// real SEV-SNP vTPM bundle whose AK quote binds this request's channel
        /// binding. Needs vTPM access, so typically prefixed with `sudo`.
        #[arg(
            long,
            default_value = "sudo /home/azureuser/unified-quote/target/release/uq azure collect"
        )]
        uq_collect: String,
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
        /// Pin the issuer's key-transparency log public key (64 hex chars,
        /// **required**). The client fetches `/kt` and refuses to use an issuer
        /// key that is not committed in the signed log — the defense against an
        /// issuer that equivocates on its key to deanonymize a client.
        #[arg(long)]
        kt_log_pub: String,
        /// A previously-observed signed head as `<seq>:<head-hex>` (printed as
        /// `kt-head` by an earlier run). When set, the client requires the
        /// current log to be a consistent *append* to it — proving a rotation
        /// didn't rewrite history.
        #[arg(long)]
        kt_known_head: Option<String>,
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

    /// Verify a clean Azure SEV-SNP vTPM bundle (no attested-TLS; the in-CVM
    /// client shape) through the real gate (`AzureUqVerifier`) and print the SNP
    /// launch measurement. The bundle is a JSON file from `uq azure collect
    /// --value-x <binding>`; binding is the 32-byte value_x the AK quote bound.
    VerifyAzure {
        /// Path to the JSON Azure bundle (from `uq azure collect`).
        #[arg(long)]
        bundle: PathBuf,
        /// Expected bound value_x (64 hex chars) = the channel binding.
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
        /// Pin the issuer's key-transparency log public key (64 hex chars,
        /// **required**). The origin only resolves/accepts issuer keys that are
        /// included in the log signed by this key.
        #[arg(long)]
        kt_log_pub: String,
    },

    /// Central double-spend authority: `POST /redeem` shared by origin replicas.
    Redeem {
        #[arg(long, default_value = "127.0.0.1:8100")]
        listen: SocketAddr,
        /// Shared spend backend URL (e.g. `redis://host:6379`) for durable,
        /// multi-replica double-spend state. Unset = in-memory. Requires the
        /// `redis` build feature.
        #[arg(long, value_name = "URL")]
        backend: Option<String>,
        /// TTL (seconds) for a retired key epoch's spent set in the backend.
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

/// Parse a `<seq>:<head-hex>` pair into a partial `SignedHead` for the
/// consistency check. Only `seq` and `head` are needed (the signature was
/// already verified when this head was first observed), so `sig` is left empty.
fn parse_known_head(s: &str) -> anyhow::Result<eat_pass_core::transparency::SignedHead> {
    let (seq, head) = s
        .trim()
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("kt-known-head must be <seq>:<head-hex>"))?;
    let seq: u64 = seq
        .parse()
        .map_err(|e| anyhow::anyhow!("kt-known-head seq: {e}"))?;
    // Validate the head is 32-byte hex up front.
    let _ = parse_hex32(head, "kt-known-head head")?;
    Ok(eat_pass_core::transparency::SignedHead {
        seq,
        head: head.trim().to_string(),
        sig: String::new(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Issuer {
            listen,
            gate,
            allow,
            class,
            class_version,
            modulus_bits,
            max_per_epoch,
            epoch_secs,
            rate_backend,
        } => {
            let backend = match gate.as_str() {
                "uq" => issuer::Backend::Uq,
                "azure" => issuer::Backend::Azure,
                "azure-tls" => issuer::Backend::AzureTls,
                other => anyhow::bail!(
                    "unknown --gate '{other}' (expected 'uq', 'azure', or 'azure-tls')"
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
                rate_backend,
            )
            .await?;
        }

        Cmd::Token {
            issuer,
            uq_collect,
            count,
            issuer_name,
            origin_info,
            present,
            kt_log_pub,
            kt_known_head,
        } => {
            let attest = client::Attest::Azure { cmd: uq_collect };
            let kt_log_pub = parse_hex32(&kt_log_pub, "kt-log-pub")?;
            let kt_known_head = kt_known_head.map(|s| parse_known_head(&s)).transpose()?;
            client::run(
                issuer,
                attest,
                count,
                issuer_name,
                origin_info,
                present,
                kt_log_pub,
                kt_known_head,
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
            listen,
            issuer,
            issuer_name,
            origin_info,
            redeemer,
            kt_log_pub,
        } => {
            let kt_log_pub = parse_hex32(&kt_log_pub, "kt-log-pub")?;
            origin::run(
                listen,
                issuer,
                issuer_name,
                origin_info,
                redeemer,
                kt_log_pub,
            )
            .await?;
        }

        Cmd::Redeem {
            listen,
            backend,
            ttl_secs,
        } => {
            redeemer::run(listen, backend, ttl_secs).await?;
        }
    }
    Ok(())
}
