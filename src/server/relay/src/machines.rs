//! Machine management for owners: enrollment codes, rename, removal, and
//! sharing with other accounts. Every change is committed to the database
//! first, then mirrored into the registry so open dashboards follow.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth::{self, CurrentUser};
use crate::db::{self, Role, ShareError};
use crate::error::ApiError;

const MAX_NAME_LEN: usize = 64;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentCode {
    /// Shown once; only its hash is stored.
    code: String,
    expires_at: i64,
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
    Ok(Json(EnrollmentCode { code, expires_at }))
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
        shares.into_iter().map(|share| ShareView { user_id: share.user_id, email: share.email, role: share.role }).collect(),
    ))
}

#[derive(Deserialize)]
pub struct ShareRequest {
    email: String,
    role: Role,
}

/// Shares the machine with an existing account, or changes its role.
pub async fn share(
    State(state): State<AppState>,
    current: CurrentUser,
    Path(machine_id): Path<String>,
    Json(body): Json<ShareRequest>,
) -> Result<StatusCode, ApiError> {
    if body.role == Role::Owner {
        return Err(ApiError::bad_request("role must be \"view\" or \"control\""));
    }
    let email = auth::normalize_email(&body.email).ok_or_else(|| ApiError::bad_request("invalid email address"))?;
    let owner_id = current.user.id;
    let now = auth::now();
    let (id, role) = (machine_id.clone(), body.role);
    let granted = state
        .db
        .call(move |conn| {
            let user_id = match db::upsert_share(conn, &id, owner_id, &email, role, now) {
                Ok(user_id) => user_id,
                Err(error) => return Ok(Err(error)),
            };
            Ok(Ok((user_id, db::machine_for_user(conn, &id, user_id)?)))
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
    if let (user_id, Some(row)) = granted {
        state.registry.grant(user_id, &row);
    }
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
