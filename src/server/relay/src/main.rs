//! Hawk relay: devices (hawk-service) and dashboards connect here, and the
//! relay routes capture commands down and video frames back up.

mod protocol;
mod registry;
mod routes;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::registry::Registry;

struct Config {
    addr: SocketAddr,
    frontend_dist: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
}

impl Config {
    /// Everything can be overridden from the environment. Paths default to
    /// the src/server layout, so `cargo run` works from a checkout.
    fn from_env() -> Result<Self, String> {
        let root = std::env::var_os("HAWK_SERVER_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
        let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
        let addr = format!("{host}:{port}").parse().map_err(|error| format!("invalid HOST/PORT: {error}"))?;
        let path_or = |var: &str, default: PathBuf| std::env::var_os(var).map(PathBuf::from).unwrap_or(default);
        Ok(Self {
            addr,
            frontend_dist: path_or("FRONTEND_DIST", root.join("frontend/dist")),
            tls_cert: path_or("TLS_CERT_PATH", root.join("certs/dev-cert.pem")),
            tls_key: path_or("TLS_KEY_PATH", root.join("certs/dev-key.pem")),
        })
    }
}

/// Loads the cert/key into a rustls config, or None when either file is
/// missing (plain http/ws for localhost-only development).
fn load_tls(config: &Config) -> Result<Option<rustls::ServerConfig>, String> {
    if !config.tls_cert.exists() || !config.tls_key.exists() {
        return Ok(None);
    }
    let certs = CertificateDer::pem_file_iter(&config.tls_cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("reading {}: {error}", config.tls_cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(&config.tls_key)
        .map_err(|error| format!("reading {}: {error}", config.tls_key.display()))?;
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("invalid TLS cert/key: {error}"))?;
    // HTTP/1.1 only: WebSocket upgrades ride on it, and the server isn't
    // built with HTTP/2 support.
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some(server))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::from_env()?;
    let registry = Arc::new(Registry::default());

    let frontend = ServeDir::new(&config.frontend_dist)
        .fallback(ServeFile::new(config.frontend_dist.join("index.html")));
    let app = Router::new()
        .route("/api/devices", get(routes::devices))
        .route("/v1/ws", get(routes::device_socket))
        .route("/v1/dashboard", get(routes::dashboard_socket))
        .fallback_service(frontend)
        .with_state(registry);

    match load_tls(&config)? {
        Some(tls) => {
            info!("relay listening at https://{}", config.addr);
            let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
            axum_server::bind_rustls(config.addr, tls)
                .serve(app.into_make_service())
                .await
                .map_err(|error| error.to_string())
        }
        None => {
            warn!(
                "no TLS cert/key found: serving plain http/ws. Run `bun run certs` for a local dev cert, \
                 or set TLS_CERT_PATH/TLS_KEY_PATH. Never expose this beyond localhost without TLS."
            );
            info!("relay listening at http://{}", config.addr);
            let listener = tokio::net::TcpListener::bind(config.addr).await.map_err(|error| error.to_string())?;
            axum::serve(listener, app).await.map_err(|error| error.to_string())
        }
    }
}
