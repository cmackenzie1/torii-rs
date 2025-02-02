use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    // Database errors
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    // Plugin errors
    #[error("Plugin error: {0}")]
    Plugin(String),
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("Plugin type mismatch: {0}")]
    PluginTypeMismatch(String),
    #[error("Unsupported auth method: {0}")]
    UnsupportedAuthMethod(String),

    // Auth errors
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User not found")]
    UserNotFound,
    #[error("User already exists")]
    UserAlreadyExists,

    // Validation errors
    #[error("Invalid email format")]
    InvalidEmailFormat,
    #[error("Weak password")]
    WeakPassword,

    // Internal server errors
    #[error("Internal server error")]
    InternalServerError,
}

impl Error {
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidCredentials | Error::UserNotFound | Error::UserAlreadyExists
        )
    }

    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            Error::InvalidEmailFormat | Error::WeakPassword | Error::InvalidCredentials
        )
    }

    pub fn is_plugin_error(&self) -> bool {
        matches!(
            self,
            Error::Plugin(_) | Error::PluginNotFound(_) | Error::PluginTypeMismatch(_)
        )
    }
}
