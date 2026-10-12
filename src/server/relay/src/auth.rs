//! Passwords, tokens, the session cookie, and login throttling.

use std::collections::HashMap;
use std::hash::Hash;
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
use crate::db::{self, AccountFlags, User};
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
    token_hash_bytes(token.as_bytes())
}

pub fn token_hash_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

pub const ENROLLMENT_TTL: time::Duration = time::Duration::hours(1);

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

/// How long a proved second factor covers step-up actions.
pub const STEP_UP_WINDOW: i64 = 5 * 60;

/// The logged-in user behind the request's session cookie. Rejects with 401
/// when there's no valid session, and while the admin requires a second
/// factor this account hasn't set up (see [`SessionUser`] for the routes
/// that stay open then).
pub struct CurrentUser {
    pub user: User,
    pub session_id: i64,
    /// When this session last proved a second factor.
    pub step_up_at: Option<i64>,
    pub account: AccountFlags,
}

impl CurrentUser {
    /// True when step-up actions need a fresh code first: the account has a
    /// second factor and this session hasn't proved it lately.
    pub fn needs_step_up(&self, now: i64) -> bool {
        self.account.mfa && self.step_up_at.is_none_or(|at| now - at >= STEP_UP_WINDOW)
    }

    /// Whether the admin's policy confines this session to setting up a
    /// second factor.
    pub fn must_set_up_mfa(&self) -> bool {
        self.account.mfa_required && !self.account.mfa
    }
}

async fn load_session(parts: &Parts, state: &AppState) -> Result<CurrentUser, ApiError> {
    let jar = CookieJar::from_headers(&parts.headers);
    let token = jar.get(SESSION_COOKIE).ok_or(ApiError::Unauthorized)?.value().to_owned();
    let hash = token_hash(&token);
    let now = now();
    let session = state.db.call(move |conn| db::find_session(conn, &hash, now)).await?.ok_or(ApiError::Unauthorized)?;
    Ok(CurrentUser { user: session.user, session_id: session.id, step_up_at: session.step_up_at, account: session.account })
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let current = load_session(parts, state).await?;
        if current.must_set_up_mfa() {
            return Err(ApiError::MfaSetupRequired);
        }
        Ok(current)
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

/// Any signed-in session, including one the admin's MFA policy confines to
/// setting up a factor: for the session itself, logout, email
/// verification and second-factor setup.
pub struct SessionUser(pub CurrentUser);

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        load_session(parts, state).await.map(Self)
    }
}

impl OptionalFromRequestParts<AppState> for SessionUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Option<Self>, Self::Rejection> {
        match load_session(parts, state).await {
            Ok(current) => Ok(Some(Self(current))),
            Err(ApiError::Unauthorized) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// A CurrentUser who has proved a second factor in the last few minutes
/// (or has none to prove): for what a stolen session shouldn't be enough
/// for. The check is here on the relay, per request.
pub struct SteppedUp(pub CurrentUser);

impl FromRequestParts<AppState> for SteppedUp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let current = <CurrentUser as FromRequestParts<AppState>>::from_request_parts(parts, state).await?;
        if current.needs_step_up(now()) {
            return Err(ApiError::StepUpRequired);
        }
        Ok(Self(current))
    }
}

/// A CurrentUser who is the instance admin; 403 otherwise. Enough for
/// reading the Admin tab; changing anything there takes [`SteppedUpAdmin`].
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

/// The admin, stepped up.
pub struct SteppedUpAdmin(pub CurrentUser);

impl FromRequestParts<AppState> for SteppedUpAdmin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let AdminUser(current) = AdminUser::from_request_parts(parts, state).await?;
        if current.needs_step_up(now()) {
            return Err(ApiError::StepUpRequired);
        }
        Ok(Self(current))
    }
}

/// Counts failures per key (a client IP, an account) and blocks the key
/// once it has too many within a window.
pub struct Throttle<K> {
    failures: Mutex<HashMap<K, (u32, Instant)>>,
    max_failures: u32,
    window: Duration,
}

/// Per-IP throttle on failed logins. Behind a reverse proxy every client
/// shares the proxy's IP, so this is a coarse brake, not account lockout.
pub type LoginLimiter = Throttle<IpAddr>;

impl Default for LoginLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(15 * 60))
    }
}

/// Per-account throttle on wrong second-factor codes, whatever address
/// they come from: a six-digit code is a small space to guess in.
pub type AccountLimiter = Throttle<i64>;

impl Default for AccountLimiter {
    fn default() -> Self {
        Self::new(10, Duration::from_secs(15 * 60))
    }
}

impl<K: Hash + Eq> Throttle<K> {
    pub fn new(max_failures: u32, window: Duration) -> Self {
        Self { failures: Mutex::new(HashMap::new()), max_failures, window }
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<K, (u32, Instant)>> {
        self.failures.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn is_blocked(&self, key: K) -> bool {
        let mut failures = self.map();
        match failures.get(&key) {
            Some((_, since)) if since.elapsed() > self.window => {
                failures.remove(&key);
                false
            }
            Some((count, _)) => *count >= self.max_failures,
            None => false,
        }
    }

    pub fn record_failure(&self, key: K) {
        let mut failures = self.map();
        let entry = failures.entry(key).or_insert((0, Instant::now()));
        if entry.1.elapsed() > self.window {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
    }

    pub fn record_success(&self, key: K) {
        self.map().remove(&key);
    }

    /// Drops windows that have expired, so the map can't grow without bound.
    pub fn prune(&self) {
        let window = self.window;
        self.map().retain(|_, (_, since)| since.elapsed() <= window);
    }
}
