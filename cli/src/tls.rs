//! TLS termination for eat-pass HTTP roles.
//!
//! Non-loopback binds **require** TLS. Loopback allows plain HTTP only with
//! `--insecure-http` (local dev).

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;

#[derive(Clone, Debug)]
pub struct TlsPaths {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

/// Enforce transport policy, then serve `app` on `listen`.
pub async fn serve(
    app: Router,
    listen: SocketAddr,
    tls: Option<TlsPaths>,
    insecure_http: bool,
    role: &str,
) -> anyhow::Result<()> {
    let loopback = listen.ip().is_loopback();
    match (loopback, tls.as_ref(), insecure_http) {
        (false, None, _) => {
            anyhow::bail!(
                "{role}: refusing cleartext on non-loopback {listen}. \
                 Pass --tls-cert and --tls-key (PEM files)."
            );
        }
        (true, None, false) => {
            anyhow::bail!(
                "{role}: plain HTTP on loopback requires --insecure-http for local dev, \
                 or pass --tls-cert and --tls-key"
            );
        }
        (_, Some(paths), _) => {
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &paths.cert_pem,
                &paths.key_pem,
            )
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "{role}: load TLS cert {} / key {}: {e}",
                    paths.cert_pem.display(),
                    paths.key_pem.display()
                )
            })?;
            eprintln!(
                "{role}: listening on https://{listen} (TLS: {})",
                paths.cert_pem.display()
            );
            axum_server::bind_rustls(listen, config)
                .serve(app.into_make_service())
                .await?;
        }
        (true, None, true) => {
            eprintln!("{role}: listening on http://{listen}  (**insecure**, loopback only)");
            let listener = tokio::net::TcpListener::bind(listen).await?;
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
