use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
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

    // Session errors
    #[error("Session not found")]
    SessionNotFound,

    // Internal server errors
    #[error("Internal server error")]
    InternalServerError,

    // Storage errors
    #[error("Storage error: {0}")]
    Storage(String),

    // Validation errors
    #[error("Validation error: {0}")]
    ValidationError(String),

    // Event errors
    #[error("Event bus error: {0}")]
    EventBus(String),

    // Migration errors
    #[error("Migration error: {0}")]
    Migration(String),
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
