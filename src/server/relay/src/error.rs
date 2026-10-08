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
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "not logged in".into()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "not allowed".into()),
            Self::NotFound => (StatusCode::NOT_FOUND, "not found".into()),
            Self::Conflict(message) => (StatusCode::CONFLICT, message),
            Self::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again later".into()),
            Self::Internal(detail) => {
                // Details go to the log, never to the client.
                error!(%detail, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
