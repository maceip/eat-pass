//! eat-pass cli internals, exposed as a library so the issuer/client/origin
//! roles and the in-process demo are unit/integration testable. The `eat-pass`
//! binary ([`main.rs`](../bin/eat-pass)) is a thin clap wrapper over these.

pub mod client;
pub mod demo;
pub mod issuer;
pub mod origin;
pub mod wire;
