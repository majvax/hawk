//! Second factors: TOTP authenticators and recovery codes, the second step
//! of a login, step-up, and the admin's reset and policy.
//!
//! An account can hold several authenticators, any of which satisfies a
//! login, so losing one phone isn't a lockout; recovery codes are the last
//! way in. Adding or removing a factor is itself a step-up action and ends
//! every other session, so a stolen session can't quietly add its own.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::api;
use crate::auth::{self, AdminUser, SessionUser, SteppedUp, SteppedUpAdmin};
use crate::db::{self, NewTotp};
use crate::error::ApiError;
use crate::totp;

const MAX_LABEL_LEN: usize = 64;
/// More authenticators than anyone needs; keeps the per-login check cheap.
const MAX_FACTORS: usize = 8;

/// Which kind of second factor a code turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    Totp,
    RecoveryCode,
}

/// Checks `code` against the account's authenticators, or failing that its
/// unused recovery codes, spending what it matched. Wrong codes count
/// against the account wherever they come from. Ok(None): wrong code.
pub async fn check_code(state: &AppState, user_id: i64, code: &str) -> Result<Option<Proof>, ApiError> {
    if state.mfa_limiter.is_blocked(user_id) {
        return Err(ApiError::TooManyRequests);
    }
    let now = auth::now();
    let secret_key = state.secret_key.clone();
    let code = code.trim().to_owned();
    let proof = state
        .db
        .call(move |conn| {
            if totp::is_totp_code(&code) {
                for factor in db::totp_factors(conn, user_id)? {
                    let Some(seed) = secret_key.open(&factor.secret, &totp::seed_context(user_id)) else { continue };
                    let Some(step) = totp::matching_step(&seed, &code, now) else { continue };
                    // A code already used (or one older than it) is refused:
                    // someone who watched it typed doesn't get to reuse it.
                    return Ok(db::use_totp_counter(conn, factor.id, step, now)?.then_some(Proof::Totp));
                }
                return Ok(None);
            }
            let hash = auth::token_hash(&totp::normalize_recovery_code(&code));
            Ok(db::use_recovery_code(conn, user_id, &hash, now)?.then_some(Proof::RecoveryCode))
        })
        .await?;
    match proof {
        Some(_) => state.mfa_limiter.record_success(user_id),
        None => state.mfa_limiter.record_failure(user_id),
    }
    Ok(proof)
}

/// Login tickets: a correct password on an account with a second factor
/// gets one of these instead of a session, to trade with a code.
pub struct LoginTickets {
    tickets: Mutex<HashMap<Vec<u8>, Ticket>>,
}

struct Ticket {
    user_id: i64,
    origin: db::SessionOrigin,
    issued: Instant,
    tries: u32,
}

/// What a ticket was issued for, once it's been traded in.
pub struct Redeemed {
    pub user_id: i64,
    pub origin: db::SessionOrigin,
}

impl Default for LoginTickets {
    fn default() -> Self {
        Self { tickets: Mutex::new(HashMap::new()) }
    }
}

impl LoginTickets {
    const TTL: Duration = Duration::from_secs(5 * 60);
    const MAX_TRIES: u32 = 5;

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, Ticket>> {
        self.tickets.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// A new ticket's token; only its hash is kept.
    pub fn issue(&self, user_id: i64, origin: db::SessionOrigin) -> String {
        let token = auth::random_token();
        let mut tickets = self.map();
        tickets.retain(|_, ticket| ticket.issued.elapsed() < Self::TTL);
        tickets.insert(auth::token_hash(&token), Ticket { user_id, origin, issued: Instant::now(), tries: 0 });
        token
    }

    /// The account a live ticket is for, counting the try. A ticket that has
    /// had its tries is gone, and the password has to be entered again.
    pub fn attempt(&self, token: &str) -> Option<i64> {
        let hash = auth::token_hash(token);
        let mut tickets = self.map();
        let ticket = tickets.get_mut(&hash)?;
        if ticket.issued.elapsed() >= Self::TTL || ticket.tries >= Self::MAX_TRIES {
            tickets.remove(&hash);
            return None;
        }
        ticket.tries += 1;
        Some(ticket.user_id)
    }

    /// Spends the ticket once its code was right.
    pub fn redeem(&self, token: &str) -> Option<Redeemed> {
        let ticket = self.map().remove(&auth::token_hash(token))?;
        Some(Redeemed { user_id: ticket.user_id, origin: ticket.origin })
    }

    pub fn prune(&self) {
        self.map().retain(|_, ticket| ticket.issued.elapsed() < Self::TTL);
    }
}

#[derive(Deserialize)]
pub struct CodeRequest {
    code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SteppedUpView {
    /// Unix seconds when step-up actions will ask again.
    until: i64,
}

/// Proves a second factor for this session: step-up actions are allowed
/// for the next few minutes, and so is control of a machine being watched.
pub async fn step_up(
    State(state): State<AppState>,
    SessionUser(current): SessionUser,
    Json(body): Json<CodeRequest>,
) -> Result<Json<SteppedUpView>, ApiError> {
    if !current.account.mfa {
        return Err(ApiError::bad_request("this account has no second factor"));
    }
    let proof = check_code(&state, current.user.id, &body.code).await?;
    let Some(proof) = proof else { return Err(ApiError::bad_request("that code isn't right")) };
    let now = auth::now();
    let session_id = current.session_id;
    state.db.call(move |conn| db::set_step_up(conn, session_id, now)).await?;
    state.registry.note_step_up(session_id, now);
    if proof == Proof::RecoveryCode {
        notify(&state, &current.user.email, "A recovery code was used to confirm an action on your account.");
    }
    Ok(Json(SteppedUpView { until: now + auth::STEP_UP_WINDOW }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorView {
    id: i64,
    label: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactorsView {
    factors: Vec<FactorView>,
    recovery_codes_left: i64,
    /// The admin requires a second factor, so the last one can't be removed.
    required: bool,
}

pub async fn list_factors(
    State(state): State<AppState>,
    SessionUser(current): SessionUser,
) -> Result<Json<FactorsView>, ApiError> {
    let user_id = current.user.id;
    let (factors, recovery_codes_left) = state
        .db
        .call(move |conn| Ok((db::list_factors(conn, user_id)?, db::unused_recovery_codes(conn, user_id)?)))
        .await?;
    Ok(Json(FactorsView {
        factors: factors
            .into_iter()
            .map(|row| FactorView {
                id: row.id,
                label: row.label,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect(),
        recovery_codes_left,
        required: current.account.mfa_required,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpSetup {
    /// Base32, for typing into an app by hand.
    secret: String,
    /// The otpauth:// URI, for a QR code.
    uri: String,
}

/// A fresh seed for a new authenticator. Nothing is stored until a code
/// from it comes back to [`add_totp`].
pub async fn totp_setup(State(state): State<AppState>, SessionUser(current): SessionUser) -> Json<TotpSetup> {
    let seed = totp::random_bytes::<{ totp::SECRET_LEN }>();
    Json(TotpSetup {
        secret: totp::base32(&seed),
        uri: totp::otpauth_uri(&state.totp_issuer, &current.user.email, &seed),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddTotp {
    secret: String,
    /// A current code from the app, which proves it was set up right.
    code: String,
    label: String,
    /// The auth key derived from the password. Needed for the first factor,
    /// which has no other factor to step up with.
    password: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedTotp {
    /// The first factor comes with recovery codes, shown this once.
    recovery_codes: Option<Vec<String>>,
}

/// Registers an authenticator once a code from it checks out. With a factor
/// already registered this is a step-up action; the first one takes the
/// password instead. Every other session is ended.
pub async fn add_totp(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    SessionUser(current): SessionUser,
    Json(body): Json<AddTotp>,
) -> Result<Json<AddedTotp>, ApiError> {
    let now = auth::now();
    let first = !current.account.mfa;
    if first {
        let password = body.password.as_deref().ok_or_else(|| ApiError::bad_request("enter your password"))?;
        api::check_password(&state, peer, current.user.id, password).await?;
    } else if current.needs_step_up(now) {
        return Err(ApiError::StepUpRequired);
    }

    let label = body.label.trim().to_owned();
    if label.is_empty() || label.chars().count() > MAX_LABEL_LEN {
        return Err(ApiError::bad_request(format!("name it in 1 to {MAX_LABEL_LEN} characters")));
    }
    let seed = totp::from_base32(&body.secret)
        .filter(|seed| seed.len() == totp::SECRET_LEN)
        .ok_or_else(|| ApiError::bad_request("invalid authenticator secret"))?;
    let Some(step) = totp::matching_step(&seed, &body.code, now) else {
        return Err(ApiError::bad_request("that code doesn't match: check the app's clock and try the next one"));
    };

    let user_id = current.user.id;
    let recovery_codes = first.then(|| (0..totp::RECOVERY_CODES).map(|_| totp::new_recovery_code()).collect::<Vec<_>>());
    let hashes: Vec<Vec<u8>> = recovery_codes
        .iter()
        .flatten()
        .map(|code| auth::token_hash(&totp::normalize_recovery_code(code)))
        .collect();
    let sealed = state.secret_key.seal(&seed, &totp::seed_context(user_id));
    let keep = current.session_id;
    state
        .db
        .call(move |conn| {
            if db::list_factors(conn, user_id)?.len() >= MAX_FACTORS {
                return Ok(false);
            }
            let factor = NewTotp { label: &label, secret: &sealed, counter: step };
            db::add_totp_factor(conn, user_id, &factor, &hashes, keep, now)?;
            // Setting it up just proved it.
            db::set_step_up(conn, keep, now)?;
            Ok(true)
        })
        .await?
        .then_some(())
        .ok_or_else(|| ApiError::Conflict(format!("an account can have at most {MAX_FACTORS} authenticators")))?;

    state.registry.close_other_sessions(user_id, keep);
    state.registry.set_mfa(user_id, true);
    state.registry.note_step_up(keep, now);
    notify(&state, &current.user.email, "An authenticator app was added to your account as a second factor.");
    Ok(Json(AddedTotp { recovery_codes }))
}

/// Removes an authenticator; a step-up action. The last one can't go while
/// the admin requires a second factor. Every other session is ended.
pub async fn remove_factor(
    State(state): State<AppState>,
    SteppedUp(current): SteppedUp,
    Path(factor_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    let user_id = current.user.id;
    let keep = current.session_id;
    let required = current.account.mfa_required;
    let outcome = state
        .db
        .call(move |conn| {
            let factors = db::list_factors(conn, user_id)?;
            if !factors.iter().any(|factor| factor.id == factor_id) {
                return Ok(None);
            }
            if required && factors.len() == 1 {
                return Ok(Some(Err(())));
            }
            db::delete_factor(conn, user_id, factor_id, keep)?;
            Ok(Some(Ok(factors.len() - 1)))
        })
        .await?
        .ok_or(ApiError::NotFound)?;
    let remaining = outcome.map_err(|()| {
        ApiError::Conflict("this server requires a second factor: add another before removing this one".into())
    })?;

    state.registry.close_other_sessions(user_id, keep);
    if remaining == 0 {
        state.registry.set_mfa(user_id, false);
    }
    notify(&state, &current.user.email, "An authenticator app was removed from your account.");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCodes {
    recovery_codes: Vec<String>,
}

/// A new set of recovery codes, replacing every old one; a step-up action.
pub async fn regenerate_recovery_codes(
    State(state): State<AppState>,
    SteppedUp(current): SteppedUp,
) -> Result<Json<RecoveryCodes>, ApiError> {
    if !current.account.mfa {
        return Err(ApiError::bad_request("add an authenticator first"));
    }
    let codes: Vec<String> = (0..totp::RECOVERY_CODES).map(|_| totp::new_recovery_code()).collect();
    let hashes: Vec<Vec<u8>> = codes.iter().map(|code| auth::token_hash(&totp::normalize_recovery_code(code))).collect();
    let user_id = current.user.id;
    state.db.call(move |conn| db::replace_recovery_codes(conn, user_id, &hashes)).await?;
    notify(&state, &current.user.email, "New recovery codes were made for your account. The old ones no longer work.");
    Ok(Json(RecoveryCodes { recovery_codes: codes }))
}

/// For a user who has lost every factor and every recovery code: removes
/// them all and ends the user's sessions, so they sign in with the password
/// alone and set up again.
pub async fn admin_reset(
    State(state): State<AppState>,
    SteppedUpAdmin(admin): SteppedUpAdmin,
    Path(user_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    if user_id == admin.user.id {
        return Err(ApiError::bad_request("manage your own second factors in Settings"));
    }
    let email = state
        .db
        .call(move |conn| {
            let email = db::user_email(conn, user_id)?;
            if email.is_some() {
                db::reset_mfa(conn, user_id)?;
            }
            Ok(email)
        })
        .await?
        .ok_or(ApiError::NotFound)?;
    state.registry.close_other_sessions(user_id, -1);
    state.registry.set_mfa(user_id, false);
    notify(&state, &email, "The server's admin removed every second factor from your account.");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    require_mfa: bool,
}

pub async fn get_policy(AdminUser(admin): AdminUser) -> Json<Policy> {
    Json(Policy { require_mfa: admin.account.mfa_required })
}

/// Requiring a second factor confines every account without one to setting
/// one up. The admin needs one first, or they'd be confined too.
pub async fn set_policy(
    State(state): State<AppState>,
    SteppedUpAdmin(admin): SteppedUpAdmin,
    Json(body): Json<Policy>,
) -> Result<Json<Policy>, ApiError> {
    if body.require_mfa && !admin.account.mfa {
        return Err(ApiError::Conflict("set up a second factor on your own account first".into()));
    }
    let value = if body.require_mfa { "1" } else { "0" };
    state.db.call(move |conn| db::set_setting(conn, "require_mfa", value)).await?;
    Ok(Json(body))
}

/// A security notice to the account's address, when there's a mailer.
pub fn notify(state: &AppState, email: &str, what: &str) {
    if let Some(mailer) = &state.mailer {
        mailer.send_notice(email, what);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> db::SessionOrigin {
        db::SessionOrigin { user_agent: None, ip: "127.0.0.1".to_owned() }
    }

    #[test]
    fn tickets_allow_a_few_tries_then_go() {
        let tickets = LoginTickets::default();
        let token = tickets.issue(7, origin());
        for _ in 0..LoginTickets::MAX_TRIES {
            assert_eq!(tickets.attempt(&token), Some(7));
        }
        assert_eq!(tickets.attempt(&token), None);
        assert!(tickets.redeem(&token).is_none());
    }

    #[test]
    fn tickets_are_spent_once() {
        let tickets = LoginTickets::default();
        let token = tickets.issue(7, origin());
        assert_eq!(tickets.attempt(&token), Some(7));
        assert_eq!(tickets.redeem(&token).map(|redeemed| redeemed.user_id), Some(7));
        assert!(tickets.redeem(&token).is_none());
        assert_eq!(tickets.attempt("not a ticket"), None);
    }
}
