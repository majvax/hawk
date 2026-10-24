//! Hawk relay: devices (hawk-service) and dashboards connect here, and the
//! relay routes capture commands down and video frames back up.

mod api;
mod audit;
mod auth;
mod db;
mod error;
mod machines;
mod mail;
mod mfa;
mod protocol;
mod quality;
mod registry;
mod e2e;
mod routes;
mod totp;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Serialize;
use tower_http::cors::{AllowOrigin, CorsLayer};
use base64::Engine;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, mpsc};
use tower_http::services::{ServeDir, ServeFile};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::audit::AuditLog;
use crate::auth::{AccountLimiter, AllowedOrigins, LoginLimiter};
use crate::db::Db;
use crate::mail::Mailer;
use crate::mfa::LoginTickets;
use crate::registry::Registry;
use crate::totp::SecretKey;

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
    /// Throttles wrong second-factor codes per account.
    pub mfa_limiter: Arc<AccountLimiter>,
    /// Logins waiting for their second factor.
    pub mfa_tickets: Arc<LoginTickets>,
    /// Seals TOTP seeds at rest.
    pub secret_key: Arc<SecretKey>,
    /// What authenticator apps list this relay's codes under.
    pub totp_issuer: Arc<str>,
    /// None when no SMTP server is configured: then nothing is mailed and
    /// email addresses are taken as given.
    pub mailer: Option<Arc<Mailer>>,
    /// Other origins that may use this relay with bearer tokens.
    pub allowed_origins: Arc<AllowedOrigins>,
    /// Where security-relevant events are recorded (see crate::audit).
    pub audit: Arc<AuditLog>,
}

struct Config {
    addr: SocketAddr,
    frontend_dist: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    db_path: PathBuf,
    /// The relay's own secret (seals TOTP seeds). Back it up with the
    /// database: without it, every authenticator has to be set up again.
    secret_key_path: PathBuf,
    /// The URL people reach the dashboard at, for links printed to the log
    /// and sent in emails.
    public_url: Option<String>,
    allowed_origins: AllowedOrigins,
    /// How many days audit events are kept; 0 for forever.
    audit_retention_days: u32,
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
        let db_path = path_or("HAWK_DB_PATH", root.join("data/hawk.db"));
        let beside_db = db_path.parent().map_or_else(|| PathBuf::from("secret.key"), |dir| dir.join("secret.key"));
        Ok(Self {
            addr,
            frontend_dist: path_or("FRONTEND_DIST", root.join("frontend/dist")),
            tls_cert: path_or("TLS_CERT_PATH", root.join("certs/dev-cert.pem")),
            tls_key: path_or("TLS_KEY_PATH", root.join("certs/dev-key.pem")),
            secret_key_path: path_or("HAWK_SECRET_KEY_PATH", beside_db),
            db_path,
            public_url: std::env::var("PUBLIC_URL").ok().map(|url| url.trim_end_matches('/').to_owned()),
            allowed_origins: AllowedOrigins::parse(&std::env::var("HAWK_ALLOWED_ORIGINS").unwrap_or_default())?,
            audit_retention_days: audit::retention_days(std::env::var("HAWK_AUDIT_RETENTION_DAYS").ok().as_deref())?,
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

/// Hourly: drop expired sessions and invites, audit events past their
/// retention, and stale login throttles.
fn spawn_cleanup(state: AppState, audit_retention_days: u32) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = auth::now();
            if let Err(error) = state.db.call(move |conn| db::purge_expired(conn, now)).await {
                error!(%error, "purging expired sessions failed");
            }
            if let Err(error) = audit::prune(&state.db, audit_retention_days, now).await {
                error!(%error, "pruning the audit log failed");
            }
            state.limiter.prune();
            state.mfa_limiter.prune();
            state.mfa_tickets.prune();
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

/// Liveness for the updater and load balancers: the relay answers and its
/// database opens. Says nothing else.
async fn healthz(State(state): State<AppState>) -> StatusCode {
    match state.db.call(|conn| conn.query_row("SELECT 1", [], |_| Ok(()))).await {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[derive(Serialize)]
struct VersionInfo {
    /// What dashboards and machines speak. A dashboard compares it with its
    /// own and says plainly which side needs updating.
    protocol: u32,
}

/// Public, so a dashboard can check it before anyone signs in. The release
/// itself isn't given out: an exact version on a public page helps nobody
/// but someone looking for a known bug.
async fn version() -> Json<VersionInfo> {
    Json(VersionInfo { protocol: protocol::PROTOCOL_VERSION })
}

/// CORS for the allowed origins: bearer tokens only, never cookies, so
/// credentials stay off.
fn cors_layer(origins: &AllowedOrigins) -> CorsLayer {
    let origins: Vec<HeaderValue> = origins.list().iter().filter_map(|origin| origin.parse().ok()).collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .expose_headers([HeaderName::from_static(auth::SESSION_TOKEN_HEADER)])
        .max_age(Duration::from_secs(60 * 60))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("hawk-relay {} (protocol {})", env!("CARGO_PKG_VERSION"), protocol::PROTOCOL_VERSION);
        return Ok(());
    }
    info!(version = env!("CARGO_PKG_VERSION"), protocol = protocol::PROTOCOL_VERSION, "hawk relay starting");

    let config = Config::from_env()?;
    if !config.allowed_origins.is_empty() {
        info!(origins = ?config.allowed_origins.list(), "dashboards on these origins may sign in with bearer tokens");
    }
    let (tls, relay_pin) = match load_tls(&config)? {
        Some((tls, pin)) => {
            info!(pin = %pin, "relay certificate pin (machines check this; see install-service.ps1 -RelayPin)");
            (Some(tls), Some(pin))
        }
        None => (None, None),
    };
    let db = Db::open(&config.db_path)?;
    info!("database at {}", config.db_path.display());

    let secret_key = SecretKey::load_or_create(&config.secret_key_path)?;

    let scheme = if tls.is_some() { "https" } else { "http" };
    let base_url = config.public_url.clone().unwrap_or_else(|| format!("{scheme}://{}", config.addr));
    bootstrap_admin(&db, &base_url).await?;
    let mailer = Mailer::from_env(&base_url)?;
    if mailer.is_some() && config.public_url.is_none() {
        warn!("PUBLIC_URL is not set: links in emails point at {base_url}");
    }
    let host = base_url.split_once("://").map_or(base_url.as_str(), |(_, host)| host);

    let (view_ended, view_ended_rx) = mpsc::unbounded_channel();
    let (audit, audit_rx) = AuditLog::new(audit::QUEUE_LEN);
    let audit = Arc::new(audit);
    audit::spawn_writer(&audit, db.clone(), audit_rx);
    match config.audit_retention_days {
        0 => info!("audit events are kept forever"),
        days => info!("audit events are kept for {days} days"),
    }
    let state = AppState {
        registry: Arc::new(Registry::new(view_ended, audit.clone())),
        db,
        limiter: Arc::new(LoginLimiter::default()),
        secure_cookies: tls.is_some(),
        relay_pin,
        shares_changed: Arc::new(Notify::new()),
        mfa_limiter: Arc::new(AccountLimiter::default()),
        mfa_tickets: Arc::new(LoginTickets::default()),
        secret_key: Arc::new(secret_key),
        totp_issuer: format!("Hawk ({host})").into(),
        mailer: mailer.map(Arc::new),
        allowed_origins: Arc::new(config.allowed_origins.clone()),
        audit,
    };
    spawn_cleanup(state.clone(), config.audit_retention_days);
    machines::spawn_share_clock(state.clone());
    machines::spawn_single_view_watch(state.clone(), view_ended_rx);

    let frontend = ServeDir::new(&config.frontend_dist)
        .fallback(ServeFile::new(config.frontend_dist.join("index.html")));
    let cors = cors_layer(&config.allowed_origins);
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/api/version", get(version))
        .route("/api/session", get(api::session))
        .route("/api/login", post(api::login))
        .route("/api/login/params", post(api::login_params))
        .route("/api/login/mfa", post(api::login_mfa))
        .route("/api/logout", post(api::logout))
        .route("/api/signup", post(api::signup))
        .route("/api/invites/{token}", get(api::invite_info))
        .route("/api/account/password", post(api::change_password))
        .route("/api/account/key", get(api::account_key))
        .route("/api/account/upgrade", post(api::upgrade_account))
        .route("/api/account/verify-email", post(api::verify_email))
        .route("/api/account/verify-email/resend", post(api::resend_verification))
        .route("/api/account/step-up", post(mfa::step_up))
        .route("/api/account/mfa", get(mfa::list_factors))
        .route("/api/account/mfa/totp/setup", post(mfa::totp_setup))
        .route("/api/account/mfa/totp", post(mfa::add_totp))
        .route("/api/account/mfa/recovery-codes", post(mfa::regenerate_recovery_codes))
        .route("/api/account/mfa/{id}", delete(mfa::remove_factor))
        .route("/api/users/lookup", post(api::lookup_user_key))
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/revoke-others", post(api::revoke_other_sessions))
        .route("/api/sessions/{id}", delete(api::revoke_session))
        .route("/api/audit", get(audit::list))
        .route("/api/admin/audit", get(audit::admin_list))
        .route("/api/admin/users", get(api::list_users))
        .route("/api/admin/users/{id}/disabled", post(api::set_user_disabled))
        .route("/api/admin/users/{id}/reset-mfa", post(mfa::admin_reset))
        .route("/api/admin/policy", get(mfa::get_policy).put(mfa::set_policy))
        .route("/api/admin/invites", get(api::list_invites).post(api::create_invite))
        .route("/api/admin/invites/{id}", delete(api::delete_invite))
        .route("/api/machines/enroll", post(machines::create_enrollment_code))
        .route("/api/machines/{id}", delete(machines::remove).patch(machines::rename))
        .route("/api/machines/{id}/endorsement", post(machines::endorse))
        .route("/api/machines/{id}/shares", get(machines::list_shares).put(machines::share))
        .route("/api/machines/{id}/shares/{user_id}", delete(machines::unshare))
        .route("/v1/ws", get(routes::device_socket))
        .route("/v1/dashboard", get(routes::dashboard_socket))
        .fallback_service(frontend)
        .layer(cors)
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
