//! eat-pass cli internals, exposed as a library so the issuer/client/origin
//! roles and the in-process demo are unit/integration testable. The `eat-pass`
//! binary ([`main.rs`](../bin/eat-pass)) is a thin clap wrapper over these.

pub mod attester;
pub mod client;
/// In-process protocol demo. Test/CI only (uses the dev-sim attestation
/// stand-ins); never compiled into the shipped binary.
#[cfg(feature = "dev-sim")]
pub mod demo;
pub mod issuer;
pub mod origin;
pub mod redeemer;
pub mod store;
pub mod tls;
pub mod wire;
