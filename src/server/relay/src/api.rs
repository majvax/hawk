//! Account endpoints: session, login/logout, invite-based signup, your own
//! password, identity key and sessions, and the admin's user and invite
//! management.
//!
//! The password never reaches the relay. The browser stretches it into an
//! auth key, which is what login, signup and password changes send as
//! "password" and what the relay hashes, and a wrapping key that encrypts the
//! account's identity key before it's stored here (see frontend/src/keys.ts).
//! Accounts from before this are "legacy" until their next login, which
//! sends the password itself one last time to upgrade them.

use std::net::SocketAddr;

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::{self, AdminUser, CurrentUser};
use crate::db::{self, NewCredentials, SignupError, User};
use crate::e2e;
use crate::error::ApiError;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserView {
    id: i64,
    email: String,
    is_admin: bool,
}

impl From<User> for UserView {
    fn from(user: User) -> Self {
        Self { id: user.id, email: user.email, is_admin: user.is_admin }
    }
}

pub async fn session(current: CurrentUser) -> Json<UserView> {
    Json(current.user.into())
}

/// What new accounts are told to use, and what an unknown email is told,
/// so the answer doesn't reveal which accounts exist.
pub const KDF: &str = "pbkdf2-sha256";
pub const DEFAULT_ITERATIONS: i64 = 600_000;
/// Fewer than this is too weak to accept; more would take a phone minutes.
const ITERATIONS_RANGE: std::ops::RangeInclusive<i64> = 100_000..=10_000_000;
/// IV, a PKCS#8 P-256 key and the GCM tag come to well under this.
const MAX_WRAPPED_KEY_LEN: usize = 512;

#[derive(Deserialize)]
pub struct EmailRequest {
    email: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginParamsView {
    /// "pbkdf2-sha256", or "legacy" for an account that still logs in with
    /// its password itself.
    kdf: String,
    iterations: i64,
}

/// How the browser should derive this account's keys from its password.
pub async fn login_params(
    State(state): State<AppState>,
    Json(body): Json<EmailRequest>,
) -> Result<Json<LoginParamsView>, ApiError> {
    let defaults = LoginParamsView { kdf: KDF.to_owned(), iterations: DEFAULT_ITERATIONS };
    let Some(email) = auth::normalize_email(&body.email) else { return Ok(Json(defaults)) };
    let params = state.db.call(move |conn| db::login_params(conn, &email)).await?;
    Ok(Json(params.map_or(defaults, |params| LoginParamsView {
        iterations: params.iterations.unwrap_or(DEFAULT_ITERATIONS),
        kdf: params.kdf,
    })))
}

/// An identity key as the browser sends it: the public half, its private
/// half encrypted under the password, and how the password was stretched.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyUpload {
    public_key: String,
    wrapped_key: String,
    iterations: i64,
}

struct DecodedKey {
    public_key: Vec<u8>,
    wrapped_key: Vec<u8>,
    iterations: i64,
}

impl KeyUpload {
    fn decode(&self) -> Result<DecodedKey, ApiError> {
        let invalid = || ApiError::bad_request("invalid identity key");
        let public_key = BASE64.decode(&self.public_key).map_err(|_| invalid())?;
        let wrapped_key = BASE64.decode(&self.wrapped_key).map_err(|_| invalid())?;
        if !e2e::is_public_key(&public_key) || wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
            return Err(invalid());
        }
        if !ITERATIONS_RANGE.contains(&self.iterations) {
            return Err(ApiError::bad_request("unsupported key derivation"));
        }
        Ok(DecodedKey { public_key, wrapped_key, iterations: self.iterations })
    }
}

#[derive(Deserialize)]
pub struct Credentials {
    email: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<Credentials>,
) -> Result<(CookieJar, Json<UserView>), ApiError> {
    let ip = peer.ip();
    if state.limiter.is_blocked(ip) {
        return Err(ApiError::TooManyRequests);
    }
    // One message for every failure, so it doesn't reveal which emails exist.
    let invalid = || ApiError::bad_request("invalid email or password");

    let Some(email) = auth::normalize_email(&body.email) else {
        state.limiter.record_failure(ip);
        return Err(invalid());
    };
    let found = state.db.call(move |conn| db::find_user_by_email(conn, &email)).await?;

    let password = body.password;
    let verified = tokio::task::spawn_blocking(move || match found {
        Some(found) if auth::verify_password(&password, &found.password_hash) => Some(found),
        Some(_) => None,
        None => {
            auth::verify_password_for_missing_user(&password);
            None
        }
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))?;

    let Some(found) = verified else {
        state.limiter.record_failure(ip);
        return Err(invalid());
    };
    if found.disabled {
        return Err(ApiError::Forbidden);
    }
    state.limiter.record_success(ip);

    let jar = start_session(&state, jar, found.user.id, session_origin(peer, &headers)).await?;
    Ok((jar, Json(found.user.into())))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
    current: Option<CurrentUser>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if let Some(current) = current {
        let session_id = current.session_id;
        state.db.call(move |conn| db::delete_session(conn, session_id)).await?;
        state.registry.close_session(session_id);
    }
    Ok((jar.remove(auth::removal_cookie()), StatusCode::NO_CONTENT))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteInfo {
    grants_admin: bool,
    expires_at: i64,
}

/// Lets the signup page tell a dead link apart from a live one before the
/// user types anything.
pub async fn invite_info(State(state): State<AppState>, Path(token): Path<String>) -> Result<Json<InviteInfo>, ApiError> {
    let hash = auth::token_hash(&token);
    let now = auth::now();
    let invite = state.db.call(move |conn| db::find_invite(conn, &hash, now)).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(InviteInfo { grants_admin: invite.grants_admin, expires_at: invite.expires_at }))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    token: String,
    email: String,
    /// The auth key derived from the password.
    password: String,
    #[serde(flatten)]
    key: KeyUpload,
}

pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(body): Json<SignupRequest>,
) -> Result<(CookieJar, Json<UserView>), ApiError> {
    let email = auth::normalize_email(&body.email).ok_or_else(|| ApiError::bad_request("invalid email address"))?;
    auth::check_password_policy(&body.password)?;
    let key = body.key.decode()?;

    let password = body.password;
    let password_hash = tokio::task::spawn_blocking(move || auth::hash_password(&password))
        .await
        .map_err(|error| ApiError::internal(error.to_string()))??;

    let invite_hash = auth::token_hash(&body.token);
    let now = auth::now();
    let user = state
        .db
        .call(move |conn| {
            let credentials = NewCredentials {
                password_hash: &password_hash,
                iterations: key.iterations,
                public_key: &key.public_key,
                wrapped_key: &key.wrapped_key,
            };
            Ok(db::redeem_invite(conn, &invite_hash, &email, &credentials, now))
        })
        .await?
        .map_err(|error| match error {
            SignupError::InvalidInvite => ApiError::bad_request("this invite link is invalid or has expired"),
            SignupError::EmailTaken => ApiError::Conflict("an account with this email already exists".into()),
            SignupError::Db(error) => error.into(),
        })?;

    let jar = start_session(&state, jar, user.id, session_origin(peer, &headers)).await?;
    Ok((jar, Json(user.into())))
}

/// Longer User-Agents are cut; they're only shown to tell sessions apart.
const MAX_USER_AGENT_LEN: usize = 512;

/// The browser and IP a sign-in came from. The IP is the TCP peer: behind a
/// reverse proxy, that's the proxy.
fn session_origin(peer: SocketAddr, headers: &HeaderMap) -> db::SessionOrigin {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|agent| agent.chars().take(MAX_USER_AGENT_LEN).collect::<String>())
        .filter(|agent| !agent.is_empty());
    db::SessionOrigin { user_agent, ip: peer.ip().to_canonical().to_string() }
}

async fn start_session(
    state: &AppState,
    jar: CookieJar,
    user_id: i64,
    origin: db::SessionOrigin,
) -> Result<CookieJar, ApiError> {
    let token = auth::random_token();
    let hash = auth::token_hash(&token);
    let now = auth::now();
    let expires_at = now + auth::SESSION_TTL.whole_seconds();
    state.db.call(move |conn| db::create_session(conn, &hash, user_id, &origin, now, expires_at)).await?;
    Ok(jar.add(auth::session_cookie(token, state.secure_cookies)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassword {
    /// Auth keys, derived from the current and the new password.
    current_password: String,
    new_password: String,
    /// The identity key, re-encrypted under the new password.
    wrapped_key: String,
}

/// Checks the current password, stores the new one's hash, and ends every
/// other session the user has. The session making the change stays.
pub async fn change_password(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    current: CurrentUser,
    Json(body): Json<ChangePassword>,
) -> Result<StatusCode, ApiError> {
    // Wrong current passwords count as failed logins, so a stolen session
    // can't be used to guess the password.
    let ip = peer.ip();
    if state.limiter.is_blocked(ip) {
        return Err(ApiError::TooManyRequests);
    }
    auth::check_password_policy(&body.new_password)?;
    let wrapped_key = BASE64.decode(&body.wrapped_key).map_err(|_| ApiError::bad_request("invalid identity key"))?;
    if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
        return Err(ApiError::bad_request("invalid identity key"));
    }

    let user_id = current.user.id;
    let old_hash = state.db.call(move |conn| db::password_hash(conn, user_id)).await?;
    let (current_password, new_password) = (body.current_password, body.new_password);
    let stored = old_hash.clone();
    let new_hash = tokio::task::spawn_blocking(move || {
        if !auth::verify_password(&current_password, &stored) {
            return Ok(None);
        }
        auth::hash_password(&new_password).map(Some)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))??;
    let Some(new_hash) = new_hash else {
        state.limiter.record_failure(ip);
        return Err(ApiError::bad_request("current password is incorrect"));
    };
    state.limiter.record_success(ip);

    let keep = current.session_id;
    let changed = state
        .db
        .call(move |conn| db::change_password(conn, user_id, &old_hash, &new_hash, &wrapped_key, keep))
        .await?;
    if !changed {
        return Err(ApiError::Conflict("your password was changed elsewhere; reload and try again".into()));
    }
    state.registry.close_other_sessions(user_id, keep);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountKeyView {
    public_key: String,
    wrapped_key: String,
}

/// The account's identity key, still encrypted under the password: the
/// browser unlocks it with the password on login. 404 for an account that
/// hasn't been upgraded yet.
pub async fn account_key(State(state): State<AppState>, current: CurrentUser) -> Result<Json<AccountKeyView>, ApiError> {
    let user_id = current.user.id;
    let key = state.db.call(move |conn| db::user_key(conn, user_id)).await?.ok_or(ApiError::NotFound)?;
    Ok(Json(AccountKeyView { public_key: BASE64.encode(key.public_key), wrapped_key: BASE64.encode(key.wrapped_key) }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeRequest {
    /// The password itself, one last time, to prove it's the account holder.
    current_password: String,
    /// The auth key derived from it, which replaces it from now on.
    password: String,
    #[serde(flatten)]
    key: KeyUpload,
}

/// Moves a legacy account to a derived auth key and gives it an identity
/// key. The browser does this right after a legacy login.
pub async fn upgrade_account(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    current: CurrentUser,
    Json(body): Json<UpgradeRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = peer.ip();
    if state.limiter.is_blocked(ip) {
        return Err(ApiError::TooManyRequests);
    }
    auth::check_password_policy(&body.password)?;
    let key = body.key.decode()?;

    let user_id = current.user.id;
    let old_hash = state.db.call(move |conn| db::password_hash(conn, user_id)).await?;
    let stored = old_hash.clone();
    let (current_password, auth_key) = (body.current_password, body.password);
    let new_hash = tokio::task::spawn_blocking(move || {
        if !auth::verify_password(&current_password, &stored) {
            return Ok(None);
        }
        auth::hash_password(&auth_key).map(Some)
    })
    .await
    .map_err(|error| ApiError::internal(error.to_string()))??;
    let Some(new_hash) = new_hash else {
        state.limiter.record_failure(ip);
        return Err(ApiError::bad_request("current password is incorrect"));
    };

    let upgraded = state
        .db
        .call(move |conn| {
            let credentials = NewCredentials {
                password_hash: &new_hash,
                iterations: key.iterations,
                public_key: &key.public_key,
                wrapped_key: &key.wrapped_key,
            };
            db::upgrade_account(conn, user_id, &old_hash, &credentials)
        })
        .await?;
    if !upgraded {
        return Err(ApiError::Conflict("this account was already upgraded; log in again".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserKeyView {
    user_id: i64,
    email: String,
    /// None until that account has logged in since keys were introduced.
    public_key: Option<String>,
}

/// Another account's identity key, to share a machine with them. The owner's
/// browser pins it the first time and shows its fingerprint to compare.
pub async fn lookup_user_key(
    State(state): State<AppState>,
    _current: CurrentUser,
    Json(body): Json<EmailRequest>,
) -> Result<Json<UserKeyView>, ApiError> {
    let email = auth::normalize_email(&body.email).ok_or_else(|| ApiError::bad_request("invalid email address"))?;
    let lookup = email.clone();
    let (user_id, public_key) = state
        .db
        .call(move |conn| db::public_key_by_email(conn, &lookup))
        .await?
        .ok_or_else(|| ApiError::bad_request("no account with that email; ask the admin to invite them first"))?;
    Ok(Json(UserKeyView { user_id, email, public_key: public_key.map(|key| BASE64.encode(key)) }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionView {
    id: i64,
    user_agent: Option<String>,
    ip: Option<String>,
    created_at: i64,
    expires_at: i64,
    /// The session this request was made with.
    current: bool,
}

pub async fn list_sessions(
    State(state): State<AppState>,
    current: CurrentUser,
) -> Result<Json<Vec<SessionView>>, ApiError> {
    let user_id = current.user.id;
    let now = auth::now();
    let sessions = state.db.call(move |conn| db::list_sessions(conn, user_id, now)).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|row| SessionView {
                id: row.id,
                user_agent: row.user_agent,
                ip: row.ip,
                created_at: row.created_at,
                expires_at: row.expires_at,
                current: row.id == current.session_id,
            })
            .collect(),
    ))
}

/// Ends one of the user's other sessions. The current one ends with logout.
pub async fn revoke_session(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(session_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    if session_id == current.session_id {
        return Err(ApiError::bad_request("use log out to end the current session"));
    }
    let user_id = current.user.id;
    let deleted = state.db.call(move |conn| db::delete_user_session(conn, user_id, session_id)).await?;
    if !deleted {
        return Err(ApiError::NotFound);
    }
    state.registry.close_session(session_id);
    Ok(StatusCode::NO_CONTENT)
}

/// Signs out everywhere else: ends every session but the current one.
pub async fn revoke_other_sessions(State(state): State<AppState>, current: CurrentUser) -> Result<StatusCode, ApiError> {
    let (user_id, keep) = (current.user.id, current.session_id);
    state.db.call(move |conn| db::delete_other_sessions(conn, user_id, keep)).await?;
    state.registry.close_other_sessions(user_id, keep);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserView {
    id: i64,
    email: String,
    is_admin: bool,
    disabled: bool,
    created_at: i64,
}

pub async fn list_users(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<Vec<AdminUserView>>, ApiError> {
    let users = state.db.call(db::list_users).await?;
    Ok(Json(
        users
            .into_iter()
            .map(|row| AdminUserView {
                id: row.user.id,
                email: row.user.email,
                is_admin: row.user.is_admin,
                disabled: row.disabled,
                created_at: row.created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct SetDisabled {
    disabled: bool,
}

pub async fn set_user_disabled(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(user_id): Path<i64>,
    Json(body): Json<SetDisabled>,
) -> Result<StatusCode, ApiError> {
    if user_id == admin.user.id {
        return Err(ApiError::bad_request("you can't disable your own account"));
    }
    let disabled = body.disabled;
    let found = state.db.call(move |conn| db::set_user_disabled(conn, user_id, disabled)).await?;
    if !found {
        return Err(ApiError::NotFound);
    }
    if disabled {
        state.registry.close_user(user_id);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteView {
    id: i64,
    created_at: i64,
    expires_at: i64,
}

pub async fn list_invites(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<Vec<InviteView>>, ApiError> {
    let now = auth::now();
    let invites = state.db.call(move |conn| db::list_pending_invites(conn, now)).await?;
    Ok(Json(
        invites
            .into_iter()
            .filter(|invite| !invite.grants_admin)
            .map(|invite| InviteView { id: invite.id, created_at: invite.created_at, expires_at: invite.expires_at })
            .collect(),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedInvite {
    id: i64,
    /// Shown once; only its hash is stored.
    token: String,
    expires_at: i64,
}

pub async fn create_invite(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
) -> Result<Json<CreatedInvite>, ApiError> {
    let token = auth::random_token();
    let hash = auth::token_hash(&token);
    let now = auth::now();
    let expires_at = now + auth::INVITE_TTL.whole_seconds();
    let admin_id = admin.user.id;
    let id = state.db.call(move |conn| db::create_invite(conn, &hash, Some(admin_id), false, now, expires_at)).await?;
    Ok(Json(CreatedInvite { id, token, expires_at }))
}

pub async fn delete_invite(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(invite_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let deleted = state.db.call(move |conn| db::delete_pending_invite(conn, invite_id)).await?;
    if deleted { Ok(StatusCode::NO_CONTENT) } else { Err(ApiError::NotFound) }
}
