//! Passwords, tokens, the session cookie, and login throttling.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::db::{self, User};
use crate::error::ApiError;

pub const SESSION_COOKIE: &str = "hawk_session";
pub const SESSION_TTL: time::Duration = time::Duration::days(30);
pub const INVITE_TTL: time::Duration = time::Duration::days(7);

pub const MIN_PASSWORD_LEN: usize = 10;
pub const MAX_PASSWORD_LEN: usize = 256;

pub fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// 32 random bytes, base64url. Used for session cookies and invite links.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Tokens are stored only as their SHA-256, so a copy of the database can't
/// be used to log in or redeem an invite.
pub fn token_hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

/// argon2id with the crate's default parameters and a random salt. CPU
/// heavy: call from the blocking pool.
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| ApiError::internal(format!("hashing password: {error}")))
}

/// CPU heavy: call from the blocking pool.
pub fn verify_password(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored)
        .is_ok_and(|hash| Argon2::default().verify_password(password.as_bytes(), &hash).is_ok())
}

/// Verifies against a fixed hash when the email is unknown, so a login
/// attempt takes about as long whether or not the account exists.
pub fn verify_password_for_missing_user(password: &str) {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| hash_password("hawk-dummy-password").unwrap_or_default());
    let _ = verify_password(password, dummy);
}

pub fn session_cookie(token: String, secure: bool) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(SESSION_TTL)
        .build()
}

pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE).path("/").build()
}

pub fn normalize_email(email: &str) -> Option<String> {
    let email = email.trim().to_lowercase();
    let valid = email.len() <= 254
        && email.split_once('@').is_some_and(|(local, domain)| !local.is_empty() && domain.contains('.'));
    valid.then_some(email)
}

pub fn check_password_policy(password: &str) -> Result<(), ApiError> {
    let length = password.chars().count();
    if length < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!("password must be at least {MIN_PASSWORD_LEN} characters")));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!("password must be at most {MAX_PASSWORD_LEN} bytes")));
    }
    Ok(())
}

/// The logged-in user behind the request's session cookie. Rejects with 401
/// when there's no valid session.
pub struct CurrentUser {
    pub user: User,
    pub session_id: i64,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar.get(SESSION_COOKIE).ok_or(ApiError::Unauthorized)?.value().to_owned();
        let hash = token_hash(&token);
        let now = now();
        let (session_id, user) =
            state.db.call(move |conn| db::find_session(conn, &hash, now)).await?.ok_or(ApiError::Unauthorized)?;
        Ok(Self { user, session_id })
    }
}

/// `Option<CurrentUser>`: None when not logged in, still an error when the
/// lookup itself fails.
impl OptionalFromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
        match <Self as FromRequestParts<AppState>>::from_request_parts(parts, state).await {
            Ok(current) => Ok(Some(current)),
            Err(ApiError::Unauthorized) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// A CurrentUser who is the instance admin; 403 otherwise.
pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let current = <CurrentUser as FromRequestParts<AppState>>::from_request_parts(parts, state).await?;
        if !current.user.is_admin {
            return Err(ApiError::Forbidden);
        }
        Ok(Self(current))
    }
}

/// Per-IP throttle on failed logins. Behind a reverse proxy every client
/// shares the proxy's IP, so this is a coarse brake, not account lockout.
#[derive(Default)]
pub struct LoginLimiter {
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl LoginLimiter {
    const MAX_FAILURES: u32 = 10;
    const WINDOW: Duration = Duration::from_secs(15 * 60);

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match failures.get(&ip) {
            Some((_, since)) if since.elapsed() > Self::WINDOW => {
                failures.remove(&ip);
                false
            }
            Some((count, _)) => *count >= Self::MAX_FAILURES,
            None => false,
        }
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let mut failures = self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() > Self::WINDOW {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).remove(&ip);
    }

    /// Drops windows that have expired, so the map can't grow without bound.
    pub fn prune(&self) {
        self.failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .retain(|_, (_, since)| since.elapsed() <= Self::WINDOW);
    }
}
