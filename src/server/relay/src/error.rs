//! The JSON error type every /api route returns.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::error;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    TooManyRequests,
    /// The action needs a second factor proved in the last few minutes;
    /// the dashboard asks for a code and tries again.
    StepUpRequired,
    /// The admin requires a second factor and this account has none yet:
    /// only setting one up is allowed until it does.
    MfaSetupRequired,
    Internal(String),
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Internal(format!("database: {error}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, json!({ "error": message })),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, json!({ "error": "not logged in" })),
            Self::Forbidden => (StatusCode::FORBIDDEN, json!({ "error": "not allowed" })),
            Self::NotFound => (StatusCode::NOT_FOUND, json!({ "error": "not found" })),
            Self::Conflict(message) => (StatusCode::CONFLICT, json!({ "error": message })),
            Self::TooManyRequests => {
                (StatusCode::TOO_MANY_REQUESTS, json!({ "error": "too many attempts, try again later" }))
            }
            Self::StepUpRequired => (
                StatusCode::FORBIDDEN,
                json!({ "error": "confirm with a code from your authenticator first", "stepUp": true }),
            ),
            Self::MfaSetupRequired => (
                StatusCode::FORBIDDEN,
                json!({ "error": "this server requires two-factor authentication: set it up first", "mfaSetup": true }),
            ),
            Self::Internal(detail) => {
                // Details go to the log, never to the client.
                error!(%detail, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": "internal error" }))
            }
        };
        (status, Json(body)).into_response()
    }
}
