use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;
use torii::ToriiError;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Invalid session token")]
    InvalidSession,

    #[error("Email already registered")]
    EmailAlreadyRegistered,

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),
}

impl From<ToriiError> for AuthError {
    fn from(err: ToriiError) -> Self {
        match err {
            ToriiError::AuthError(msg) => {
                if msg.contains("already exists") || msg.contains("already registered") {
                    AuthError::EmailAlreadyRegistered
                } else if msg.contains("Invalid") || msg.contains("incorrect") {
                    AuthError::InvalidCredentials
                } else {
                    AuthError::AuthenticationFailed(msg)
                }
            }
            ToriiError::StorageError(msg) => {
                if msg.contains("not found") {
                    if msg.contains("User") {
                        AuthError::UserNotFound
                    } else if msg.contains("Session") {
                        AuthError::SessionNotFound
                    } else {
                        AuthError::InternalError(msg)
                    }
                } else {
                    AuthError::InternalError(msg)
                }
            }
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::AuthenticationFailed(ref msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
            AuthError::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found"),
            AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid session"),
            AuthError::EmailAlreadyRegistered => (StatusCode::CONFLICT, "Email already registered"),
            AuthError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AuthError::InternalError(ref msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str()),
            AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            AuthError::FeatureNotEnabled(ref feature) => {
                (StatusCode::NOT_IMPLEMENTED, feature.as_str())
            }
        };

        let body = Json(json!({
            "error": error_message,
            "code": status.as_u16()
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;
