use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
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

    #[error("Invalid request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    #[error("Account is temporarily locked")]
    AccountLocked {
        /// Seconds until the account can be accessed again
        retry_after_seconds: i64,
    },
}

impl From<ToriiError> for AuthError {
    fn from(err: ToriiError) -> Self {
        match err {
            ToriiError::AuthError(msg) => {
                // Check for account locked error
                if msg.contains("Account is temporarily locked") {
                    // Parse retry_after from the message if present
                    let retry_after = msg
                        .split("Retry after ")
                        .nth(1)
                        .and_then(|s| s.split(' ').next())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    AuthError::AccountLocked {
                        retry_after_seconds: retry_after,
                    }
                } else if msg.contains("Invalid") || msg.contains("incorrect") {
                    // Use generic InvalidCredentials to prevent user enumeration attacks.
                    // Do not reveal whether a user exists or not through error messages.
                    AuthError::InvalidCredentials
                } else {
                    AuthError::AuthenticationFailed(msg)
                }
            }
            ToriiError::StorageError(msg) => {
                if msg.contains("not found") {
                    if msg.contains("Session") {
                        AuthError::SessionNotFound
                    } else {
                        // Use generic error to prevent user enumeration
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
        match self {
            AuthError::AccountLocked {
                retry_after_seconds,
            } => {
                let body = Json(json!({
                    "error": "Account is temporarily locked",
                    "code": StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    "retry_after_seconds": retry_after_seconds
                }));

                let mut response = (StatusCode::TOO_MANY_REQUESTS, body).into_response();

                // Add Retry-After header if we have a positive retry time
                if retry_after_seconds > 0
                    && let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string())
                {
                    response.headers_mut().insert(header::RETRY_AFTER, value);
                }

                response
            }
            _ => {
                let (status, error_message) = match &self {
                    AuthError::AuthenticationFailed(msg) => {
                        (StatusCode::UNAUTHORIZED, msg.as_str())
                    }
                    AuthError::InvalidCredentials => {
                        (StatusCode::UNAUTHORIZED, "Invalid credentials")
                    }
                    AuthError::UserNotFound => (StatusCode::NOT_FOUND, "User not found"),
                    AuthError::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found"),
                    AuthError::InvalidSession => (StatusCode::UNAUTHORIZED, "Invalid session"),
                    AuthError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
                    AuthError::InternalError(msg) => {
                        (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
                    }
                    AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
                    AuthError::FeatureNotEnabled(feature) => {
                        (StatusCode::NOT_IMPLEMENTED, feature.as_str())
                    }
                    AuthError::AccountLocked { .. } => {
                        unreachable!("Handled in outer match arm")
                    }
                };

                let body = Json(json!({
                    "error": error_message,
                    "code": status.as_u16()
                }));

                (status, body).into_response()
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, AuthError>;
