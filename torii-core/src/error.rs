use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Authentication error: {0}")]
    Auth(#[from] AuthError),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Validation error: {0}")]
    Validation(#[from] ValidationError),

    #[error("Event error: {0}")]
    Event(#[from] EventError),

    #[error("Session error: {0}")]
    Session(#[from] SessionError),
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

    #[error("Unsupported authentication method: {0}")]
    UnsupportedMethod(String),

    #[error("Account already linked")]
    AccountAlreadyLinked,

    #[error("Password hash error: {0}")]
    PasswordHashError(String),
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,

    #[error("Session expired")]
    Expired,

    #[error("Session already exists")]
    AlreadyExists,

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("JWT verification failed: {0}")]
    JwtVerification(String),
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
pub enum ValidationError {
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

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
            Error::Validation(ValidationError::InvalidEmail(_))
                | Error::Validation(ValidationError::WeakPassword)
                | Error::Validation(ValidationError::InvalidField(_))
                | Error::Validation(ValidationError::MissingField(_))
        )
    }

}
