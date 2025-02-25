use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Plugin error: {0}")]
    Plugin(#[from] PluginError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Event error: {0}")]
    Event(#[from] EventError),
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Email not verified")]
    EmailNotVerified,

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Unsupported authentication method: {0}")]
    UnsupportedMethod(String),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Record not found")]
    NotFound,
}

#[derive(Debug, Error)]
pub enum PluginError {
    #[error("Plugin not found: {0}")]
    NotFound(String),

    #[error("Plugin initialization failed: {0}")]
    InitializationFailed(String),

    #[error("Plugin type mismatch: {0}")]
    TypeMismatch(String),

    #[error("Plugin operation failed: {0}")]
    OperationFailed(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Weak password")]
    WeakPassword,

    #[error("Invalid field: {0}")]
    InvalidField(String),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("Event bus error: {0}")]
    BusError(String),

    #[error("Event handler error: {0}")]
    HandlerError(String),
}

impl Error {
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            Error::Auth(AuthError::InvalidCredentials)
                | Error::Auth(AuthError::UserNotFound)
                | Error::Auth(AuthError::UserAlreadyExists)
        )
    }

    pub fn is_validation_error(&self) -> bool {
        matches!(
            self,
            Error::Validation(ValidationError::InvalidEmail)
                | Error::Validation(ValidationError::WeakPassword)
                | Error::Validation(ValidationError::InvalidField(_))
                | Error::Validation(ValidationError::MissingField(_))
        )
    }

    pub fn is_plugin_error(&self) -> bool {
        matches!(
            self,
            Error::Plugin(PluginError::NotFound(_))
                | Error::Plugin(PluginError::TypeMismatch(_))
                | Error::Plugin(PluginError::OperationFailed(_))
        )
    }
}
