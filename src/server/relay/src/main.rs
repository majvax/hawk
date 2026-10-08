//! Hawk relay: devices (hawk-service) and dashboards connect here, and the
//! relay routes capture commands down and video frames back up.

mod api;
mod auth;
mod db;
mod error;
mod machines;
mod protocol;
mod registry;
mod routes;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{delete, get, post};
use base64::Engine;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, mpsc};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::auth::LoginLimiter;
use crate::db::Db;
use crate::registry::Registry;

/// Shared by every handler.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub db: Db,
    pub limiter: Arc<LoginLimiter>,
    /// Session cookies get the Secure flag whenever we serve TLS.
    pub secure_cookies: bool,
    /// SHA-256 of the TLS certificate's public key (SPKI), base64: what
    /// machines pin. None when serving without TLS.
    pub relay_pin: Option<String>,
    /// Wakes the share clock when a share's start or expiry changes.
    pub shares_changed: Arc<Notify>,
}

struct Config {
    addr: SocketAddr,
    frontend_dist: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    db_path: PathBuf,
    /// The URL people reach the dashboard at, for links printed to the log.
    public_url: Option<String>,
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
            db_path: path_or("HAWK_DB_PATH", root.join("data/hawk.db")),
            public_url: std::env::var("PUBLIC_URL").ok().map(|url| url.trim_end_matches('/').to_owned()),
        })
    }
}

/// With no accounts yet, prints a one-time admin invite to the log. Only
/// someone who can read the server's output can claim the instance, so
/// there's no window where a stranger could register first.
async fn bootstrap_admin(db: &Db, base_url: &str) -> Result<(), String> {
    let token = auth::random_token();
    let hash = auth::token_hash(&token);
    let now = auth::now();
    let expires_at = now + auth::INVITE_TTL.whole_seconds();
    let created = db
        .call(move |conn| {
            if db::user_count(conn)? > 0 {
                return Ok(false);
            }
            db::delete_pending_admin_invites(conn)?;
            db::create_invite(conn, &hash, None, true, now, expires_at)?;
            Ok(true)
        })
        .await
        .map_err(|error| error.to_string())?;
    if created {
        warn!("no accounts yet. Create the admin account at: {base_url}/invite/{token}");
    }
    Ok(())
}

/// Hourly: drop expired sessions and invites, and stale login throttles.
fn spawn_cleanup(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = auth::now();
            if let Err(error) = state.db.call(move |conn| db::purge_expired(conn, now)).await {
                error!(%error, "purging expired sessions failed");
            }
            state.limiter.prune();
        }
    });
}

/// The pin machines check the relay against: base64 SHA-256 of the leaf
/// certificate's SubjectPublicKeyInfo. Pinning the key rather than the whole
/// certificate survives renewals that keep the key.
fn spki_pin(cert: &CertificateDer<'_>) -> Result<String, String> {
    let parsed = webpki::EndEntityCert::try_from(cert).map_err(|error| format!("parsing TLS certificate: {error}"))?;
    let digest = Sha256::digest(parsed.subject_public_key_info().as_ref());
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

/// Loads the cert/key into a rustls config (and the cert's pin), or None
/// when either file is missing (plain http/ws for localhost-only development).
fn load_tls(config: &Config) -> Result<Option<(rustls::ServerConfig, String)>, String> {
    if !config.tls_cert.exists() || !config.tls_key.exists() {
        return Ok(None);
    }
    let certs = CertificateDer::pem_file_iter(&config.tls_cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("reading {}: {error}", config.tls_cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(&config.tls_key)
        .map_err(|error| format!("reading {}: {error}", config.tls_key.display()))?;
    let pin = spki_pin(certs.first().ok_or_else(|| format!("no certificate in {}", config.tls_cert.display()))?)?;
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| format!("invalid TLS cert/key: {error}"))?;
    // HTTP/1.1 only: WebSocket upgrades ride on it, and the server isn't
    // built with HTTP/2 support.
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Some((server, pin)))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = Config::from_env()?;
    let (tls, relay_pin) = match load_tls(&config)? {
        Some((tls, pin)) => {
            info!(pin = %pin, "relay certificate pin (machines check this; see install-service.ps1 -RelayPin)");
            (Some(tls), Some(pin))
        }
        None => (None, None),
    };
    let db = Db::open(&config.db_path)?;
    info!("database at {}", config.db_path.display());

    let scheme = if tls.is_some() { "https" } else { "http" };
    let base_url = config.public_url.clone().unwrap_or_else(|| format!("{scheme}://{}", config.addr));
    bootstrap_admin(&db, &base_url).await?;

    let (view_ended, view_ended_rx) = mpsc::unbounded_channel();
    let state = AppState {
        registry: Arc::new(Registry::new(view_ended)),
        db,
        limiter: Arc::new(LoginLimiter::default()),
        secure_cookies: tls.is_some(),
        relay_pin,
        shares_changed: Arc::new(Notify::new()),
    };
    spawn_cleanup(state.clone());
    machines::spawn_share_clock(state.clone());
    machines::spawn_single_view_watch(state.clone(), view_ended_rx);

    let frontend = ServeDir::new(&config.frontend_dist)
        .fallback(ServeFile::new(config.frontend_dist.join("index.html")));
    let app = Router::new()
        .route("/api/session", get(api::session))
        .route("/api/login", post(api::login))
        .route("/api/logout", post(api::logout))
        .route("/api/signup", post(api::signup))
        .route("/api/invites/{token}", get(api::invite_info))
        .route("/api/account/password", post(api::change_password))
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/revoke-others", post(api::revoke_other_sessions))
        .route("/api/sessions/{id}", delete(api::revoke_session))
        .route("/api/admin/users", get(api::list_users))
        .route("/api/admin/users/{id}/disabled", post(api::set_user_disabled))
        .route("/api/admin/invites", get(api::list_invites).post(api::create_invite))
        .route("/api/admin/invites/{id}", delete(api::delete_invite))
        .route("/api/machines/enroll", post(machines::create_enrollment_code))
        .route("/api/machines/{id}", delete(machines::remove).patch(machines::rename))
        .route("/api/machines/{id}/shares", get(machines::list_shares).put(machines::share))
        .route("/api/machines/{id}/shares/{user_id}", delete(machines::unshare))
        .route("/v1/ws", get(routes::device_socket))
        .route("/v1/dashboard", get(routes::dashboard_socket))
        .fallback_service(frontend)
        .with_state(state)
        .into_make_service_with_connect_info::<SocketAddr>();

    match tls {
        Some(tls) => {
            info!("relay listening at https://{}", config.addr);
            let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
            axum_server::bind_rustls(config.addr, tls).serve(app).await.map_err(|error| error.to_string())
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
