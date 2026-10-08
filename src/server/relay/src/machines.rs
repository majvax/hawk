//! Machine management for owners: enrollment codes, rename, removal, and
//! sharing with other accounts, permanently or temporarily. Every change is
//! committed to the database first, then mirrored into the registry so open
//! dashboards follow.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, Role, ShareError, ShareTerms};
use crate::error::ApiError;
use crate::registry::ViewEnded;

const MAX_NAME_LEN: usize = 64;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentCode {
    /// Shown once; only its hash is stored.
    code: String,
    expires_at: i64,
    /// What the machine should pin the relay's TLS key to; None without TLS.
    relay_pin: Option<String>,
}

/// A one-time code that enrolls one machine under the caller's account.
pub async fn create_enrollment_code(
    State(state): State<AppState>,
    current: CurrentUser,
) -> Result<Json<EnrollmentCode>, ApiError> {
    let code = auth::enrollment_code();
    let hash = auth::enrollment_code_hash(&code);
    let now = auth::now();
    let expires_at = now + auth::ENROLLMENT_TTL.whole_seconds();
    let owner_id = current.user.id;
    state.db.call(move |conn| db::create_enrollment_code(conn, &hash, owner_id, now, expires_at)).await?;
    Ok(Json(EnrollmentCode { code, expires_at, relay_pin: state.relay_pin.clone() }))
}

#[derive(Deserialize)]
pub struct Rename {
    name: String,
}

pub async fn rename(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
    Json(body): Json<Rename>,
) -> Result<StatusCode, ApiError> {
    let name = body.name.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(ApiError::bad_request(format!("name must be 1 to {MAX_NAME_LEN} characters")));
    }
    let owner_id = current.user.id;
    let (id, new_name) = (machine_id.clone(), name.clone());
    state
        .db
        .call(move |conn| db::rename_machine(conn, &id, owner_id, &new_name))
        .await?
        .ok_or(ApiError::NotFound)?;
    state.registry.rename(&machine_id, &name);
    Ok(StatusCode::NO_CONTENT)
}

/// Removes the machine: its credential stops working, it's disconnected,
/// and everyone it was shared with loses it.
pub async fn remove(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let owner_id = current.user.id;
    let id = machine_id.clone();
    if !state.db.call(move |conn| db::delete_machine(conn, &id, owner_id)).await? {
        return Err(ApiError::NotFound);
    }
    state.registry.remove_machine(&machine_id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareView {
    user_id: i64,
    email: String,
    role: Role,
    starts_at: Option<i64>,
    expires_at: Option<i64>,
    single_view: bool,
}

pub async fn list_shares(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
) -> Result<Json<Vec<ShareView>>, ApiError> {
    let owner_id = current.user.id;
    let shares = state
        .db
        .call(move |conn| db::list_shares(conn, &machine_id, owner_id))
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(
        shares
            .into_iter()
            .map(|share| ShareView {
                user_id: share.user_id,
                email: share.email,
                role: share.terms.role,
                starts_at: share.terms.starts_at,
                expires_at: share.terms.expires_at,
                single_view: share.terms.single_view,
            })
            .collect(),
    ))
}

/// How far ahead a temporary share may start, and how long it may last.
const MAX_SHARE_HORIZON: i64 = 366 * 24 * 60 * 60;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareRequest {
    email: String,
    role: Role,
    /// Unix seconds; omitted, null or past: access starts now.
    #[serde(default)]
    starts_at: Option<i64>,
    /// Unix seconds; omitted or null: until revoked.
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    single_view: bool,
}

impl ShareRequest {
    fn terms(&self, now: i64) -> Result<ShareTerms, ApiError> {
        if self.role == Role::Owner {
            return Err(ApiError::bad_request("role must be \"view\" or \"control\""));
        }
        let starts_at = self.starts_at.filter(|&starts_at| starts_at > now);
        let begins = starts_at.unwrap_or(now);
        if begins > now + MAX_SHARE_HORIZON {
            return Err(ApiError::bad_request("a share can start at most a year from now"));
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= begins {
                return Err(ApiError::bad_request("a share must end after it starts"));
            }
            if expires_at > begins + MAX_SHARE_HORIZON {
                return Err(ApiError::bad_request("a temporary share can last at most a year"));
            }
        }
        Ok(ShareTerms { role: self.role, starts_at, expires_at: self.expires_at, single_view: self.single_view })
    }
}

/// Shares the machine with an existing account, or replaces the terms of
/// an existing share. A share that starts later is granted when it starts.
pub async fn share(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
    Json(body): Json<ShareRequest>,
) -> Result<StatusCode, ApiError> {
    let now = auth::now();
    let terms = body.terms(now)?;
    let email = auth::normalize_email(&body.email).ok_or_else(|| ApiError::bad_request("invalid email address"))?;
    let owner_id = current.user.id;
    let id = machine_id.clone();
    let granted = state
        .db
        .call(move |conn| {
            let user_id = match db::upsert_share(conn, &id, owner_id, &email, terms, now) {
                Ok(user_id) => user_id,
                Err(error) => return Ok(Err(error)),
            };
            Ok(Ok((user_id, db::machine_for_user(conn, &id, user_id, now)?)))
        })
        .await?
        .map_err(|error| match error {
            ShareError::NotOwner => ApiError::NotFound,
            ShareError::NoSuchUser => {
                ApiError::bad_request("no account with that email; ask the admin to invite them first")
            }
            ShareError::SelfShare => ApiError::bad_request("you already own this machine"),
            ShareError::Db(error) => error.into(),
        })?;
    match granted {
        (user_id, Some(row)) => state.registry.grant(user_id, &row),
        // Starts later: if it was live before this change, it isn't now.
        (user_id, None) => state.registry.revoke(user_id, &machine_id),
    }
    state.shares_changed.notify_one();
    Ok(StatusCode::NO_CONTENT)
}

/// Revokes a share; the user's live view of the machine stops immediately.
pub async fn unshare(
    State(state): State<AppState>,
    current: CurrentUser,
    Path((machine_id, user_id)): Path<(String, i64)>,
) -> Result<StatusCode, ApiError> {
    let owner_id = current.user.id;
    let id = machine_id.clone();
    if !state.db.call(move |conn| db::delete_share(conn, &id, owner_id, user_id)).await? {
        return Err(ApiError::NotFound);
    }
    state.registry.revoke(user_id, &machine_id);
    Ok(StatusCode::NO_CONTENT)
}

/// Grants shares as they start and revokes them as they expire, cutting off
/// live viewers exactly like a manual revoke. Sleeps until the next start
/// or expiry, or until `shares_changed` says the schedule moved.
pub fn spawn_share_clock(state: AppState) {
    tokio::spawn(async move {
        // Dashboards opened before now read their access from the database,
        // so only shares starting after now need granting.
        let mut checked_until = auth::now();
        loop {
            let now = auth::now();
            if let Err(error) = apply_share_schedule(&state, checked_until, now).await {
                error!(%error, "share clock: applying the share schedule failed");
            }
            checked_until = now;

            let next = state.db.call(move |conn| db::next_share_deadline(conn, now)).await.unwrap_or_else(|error| {
                error!(%error, "share clock: reading the next deadline failed");
                None
            });
            // At least a second, so a deadline within this second doesn't spin.
            let wait = next.map_or(3600, |deadline| (deadline - now).clamp(1, 3600));
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(wait.unsigned_abs())) => {}
                () = state.shares_changed.notified() => {}
            }
        }
    });
}

async fn apply_share_schedule(state: &AppState, after: i64, now: i64) -> Result<(), rusqlite::Error> {
    for share in state.db.call(move |conn| db::take_expired_shares(conn, now)).await? {
        info!(machine = %share.public_id, user_id = share.user_id, "share expired");
        state.registry.revoke(share.user_id, &share.public_id);
    }
    for share in state.db.call(move |conn| db::shares_started_between(conn, after, now)).await? {
        let db::ShareKey { public_id, user_id } = share;
        info!(machine = %public_id, user_id, "share started");
        let lookup = public_id.clone();
        if let Some(row) = state.db.call(move |conn| db::machine_for_user(conn, &lookup, user_id, now)).await? {
            state.registry.grant(user_id, &row);
        }
    }
    Ok(())
}

/// How long a viewer whose dashboard dropped has to come back before their
/// single-view share counts as used: long enough for the dashboard to
/// reconnect and resume after a network blip.
const SINGLE_VIEW_GRACE: Duration = Duration::from_secs(60);

/// Uses up single-view shares as their viewing ends (see [`ViewEnded`]).
pub fn spawn_single_view_watch(state: AppState, mut ended: mpsc::UnboundedReceiver<ViewEnded>) {
    tokio::spawn(async move {
        while let Some(view) = ended.recv().await {
            let state = state.clone();
            tokio::spawn(async move {
                if !view.immediate {
                    tokio::time::sleep(SINGLE_VIEW_GRACE).await;
                    if state.registry.is_watching(view.user_id, &view.machine_id) {
                        return;
                    }
                }
                let (id, user_id) = (view.machine_id.clone(), view.user_id);
                match state.db.call(move |conn| db::delete_single_view_share(conn, &id, user_id)).await {
                    Ok(true) => {
                        info!(machine = %view.machine_id, user_id, "single-view share used up");
                        state.registry.revoke(user_id, &view.machine_id);
                    }
                    Ok(false) => {}
                    Err(error) => error!(%error, "using up a single-view share failed"),
                }
            });
        }
    });
}
