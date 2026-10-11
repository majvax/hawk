//! Machine management for owners: enrollment codes, endorsing a machine's
//! key, rename, removal, and sharing with other accounts, permanently or
//! temporarily. Every change is committed to the database first, then
//! mirrored into the registry so open dashboards follow.
//!
//! Who may watch a machine is decided by its owner's signatures, which the
//! machine checks itself (see crate::e2e): sharing stores the grant the
//! owner's browser signed, and revoking stores a signed revocation the
//! machine is sent.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, Role, ShareError, ShareTerms, Signed};
use crate::e2e;
use crate::error::ApiError;
use crate::protocol::SignedView;
use crate::registry::ViewEnded;

const MAX_NAME_LEN: usize = 64;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentRequest {
    /// Base64 SHA-256 of the code's canonical form. The code itself is made
    /// in the owner's browser and never sent here: it keys the bindings
    /// that let the machine and the owner trust each other's keys.
    code_hash: String,
    /// Base64 HMAC of the owner's identity key under the code.
    owner_binding: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentCode {
    expires_at: i64,
    /// What the machine should pin the relay's TLS key to; None without TLS.
    relay_pin: Option<String>,
}

/// Registers a one-time code that enrolls one machine under the caller's
/// account.
pub async fn create_enrollment_code(
    State(state): State<AppState>,
    current: CurrentUser,
    Json(body): Json<EnrollmentRequest>,
) -> Result<Json<EnrollmentCode>, ApiError> {
    let invalid = || ApiError::bad_request("invalid enrollment code");
    let hash = BASE64.decode(&body.code_hash).map_err(|_| invalid())?;
    let binding = BASE64.decode(&body.owner_binding).map_err(|_| invalid())?;
    if hash.len() != 32 || binding.len() != 32 {
        return Err(invalid());
    }
    let owner_id = current.user.id;
    if state.db.call(move |conn| db::user_key(conn, owner_id)).await?.is_none() {
        return Err(ApiError::Conflict("set up your account's key first: log out and in again".into()));
    }
    let now = auth::now();
    let expires_at = now + auth::ENROLLMENT_TTL.whole_seconds();
    state.db.call(move |conn| db::create_enrollment_code(conn, &hash, owner_id, &binding, now, expires_at)).await?;
    Ok(Json(EnrollmentCode { expires_at, relay_pin: state.relay_pin.clone() }))
}

#[derive(Deserialize)]
pub struct Endorsement {
    /// Base64 signature of the owner over e2e::machine_statement.
    signature: String,
}

/// Stores the owner's endorsement of their machine's key, which viewers
/// check before trusting anything the machine signs. The owner's browser
/// signs it once it has checked the machine's enrollment binding, or the
/// owner compared fingerprints.
pub async fn endorse(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
    Json(body): Json<Endorsement>,
) -> Result<StatusCode, ApiError> {
    let owner_id = current.user.id;
    let id = machine_id.clone();
    let (machine_key, owner_key) =
        state.db.call(move |conn| db::endorsement_keys(conn, &id, owner_id)).await?.ok_or(ApiError::NotFound)?;
    let signature = BASE64.decode(&body.signature).map_err(|_| ApiError::bad_request("invalid signature"))?;
    let signed = Signed { statement: e2e::machine_statement(&machine_id, &machine_key), signature };
    if !e2e::verify(&owner_key, &signed) {
        return Err(ApiError::bad_request("the signature doesn't match your key"));
    }
    let id = machine_id.clone();
    state.db.call(move |conn| db::set_endorsement(conn, &id, owner_id, &signed.signature)).await?;
    refresh_everyone(&state, &machine_id, owner_id).await
}

/// Re-sends the machine to its owner and everyone it's shared with.
async fn refresh_everyone(state: &AppState, machine_id: &str, owner_id: i64) -> Result<StatusCode, ApiError> {
    let id = machine_id.to_owned();
    let now = auth::now();
    let rows = state
        .db
        .call(move |conn| {
            let mut users = vec![owner_id];
            users.extend(db::list_shares(conn, &id, owner_id)?.unwrap_or_default().iter().map(|share| share.user_id));
            let mut rows = Vec::new();
            for user_id in users {
                if let Some(row) = db::machine_for_user(conn, &id, user_id, now)? {
                    rows.push((user_id, row));
                }
            }
            Ok(rows)
        })
        .await?;
    for (user_id, row) in rows {
        state.registry.grant(user_id, &row);
    }
    Ok(StatusCode::NO_CONTENT)
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
    /// The recipient's identity key; None until they've set one up.
    public_key: Option<String>,
    /// What the owner signed for this share; None for a share from before
    /// grants existed, which the owner's browser signs when it next can.
    grant: Option<SignedView>,
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
                public_key: share.public_key.map(|key| BASE64.encode(key)),
                grant: share.grant.as_ref().map(SignedView::from),
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
    /// The owner's signature over exactly these terms, for the recipient's
    /// current identity key (see e2e::check_grant).
    grant: SignedView,
}

impl ShareRequest {
    fn terms(&self, now: i64) -> Result<ShareTerms, ApiError> {
        if self.role == Role::Owner {
            return Err(ApiError::bad_request("role must be \"view\", \"control\" or \"dev\""));
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
    let grant = body.grant.decode().ok_or_else(|| ApiError::bad_request("invalid grant"))?;
    let owner_id = current.user.id;

    let lookup = email.clone();
    let (user_id, viewer_key) = state
        .db
        .call(move |conn| db::public_key_by_email(conn, &lookup))
        .await?
        .ok_or_else(|| ApiError::bad_request("no account with that email; ask the admin to invite them first"))?;
    let viewer_key = viewer_key.ok_or_else(|| {
        ApiError::bad_request("that account hasn't set up its key yet; ask them to log in once, then share again")
    })?;
    let owner_key = state.db.call(move |conn| db::user_key(conn, owner_id)).await?.ok_or(ApiError::Forbidden)?.public_key;
    e2e::check_grant(&grant, &owner_key, &machine_id, &viewer_key, &terms)
        .map_err(|mismatch| ApiError::bad_request(mismatch.message()))?;

    let id = machine_id.clone();
    let granted = state
        .db
        .call(move |conn| {
            if let Err(error) = db::upsert_share(conn, &id, owner_id, user_id, terms, &grant, now) {
                return Ok(Err(error));
            }
            Ok(Ok((user_id, db::machine_for_user(conn, &id, user_id, now)?)))
        })
        .await?
        .map_err(|error| match error {
            ShareError::NotOwner => ApiError::NotFound,
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

#[derive(Deserialize)]
pub struct UnshareRequest {
    /// The owner's signed revocation; required once the share has a grant,
    /// since the machine would otherwise keep honouring it.
    #[serde(default)]
    revocation: Option<SignedView>,
}

/// Revokes a share; the user's live view of the machine stops immediately,
/// and the machine is handed the signed revocation.
pub async fn unshare(
    State(state): State<AppState>,
    current: CurrentUser,
    Path((machine_id, user_id)): Path<(String, i64)>,
    Json(body): Json<UnshareRequest>,
) -> Result<StatusCode, ApiError> {
    let owner_id = current.user.id;
    let id = machine_id.clone();
    let share = state
        .db
        .call(move |conn| db::share_for(conn, &id, owner_id, user_id))
        .await?
        .ok_or(ApiError::NotFound)?;
    let revocation = match (&share.grant, &share.public_key, body.revocation) {
        (None, _, _) => None,
        (Some(grant), Some(viewer_key), Some(revocation)) => {
            let revocation = revocation.decode().ok_or_else(|| ApiError::bad_request("invalid revocation"))?;
            let owner_key =
                state.db.call(move |conn| db::user_key(conn, owner_id)).await?.ok_or(ApiError::Forbidden)?.public_key;
            e2e::check_revocation(&revocation, &owner_key, &machine_id, viewer_key, Some(grant))
                .map_err(|mismatch| ApiError::bad_request(mismatch.message()))?;
            Some(revocation)
        }
        (Some(_), _, _) => return Err(ApiError::bad_request("a signed revocation is required")),
    };

    let id = machine_id.clone();
    let now = auth::now();
    if !state.db.call(move |conn| db::delete_share(conn, &id, owner_id, user_id, revocation.as_ref(), now)).await? {
        return Err(ApiError::NotFound);
    }
    state.registry.revoke(user_id, &machine_id);
    let id = machine_id.clone();
    let revocations = state.db.call(move |conn| db::revocations(conn, &id)).await?;
    state.registry.send_revocations(&machine_id, &revocations);
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
