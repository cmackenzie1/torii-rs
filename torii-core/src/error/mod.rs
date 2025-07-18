pub mod utilities;

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

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
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

    #[error("Constraint violation: {0}")]
    Constraint(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Weak password")]
    WeakPassword,

    #[error("Invalid name: {0}")]
    InvalidName(String),

    #[error("Invalid user ID: {0}")]
    InvalidUserId(String),

    #[error("Invalid provider: {0}")]
    InvalidProvider(String),

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

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("JWT signing failed: {0}")]
    JwtSigning(String),

    #[error("JWT verification failed: {0}")]
    JwtVerification(String),

    #[error("Password hashing failed: {0}")]
    PasswordHash(String),

    #[error("Passkey operation failed: {0}")]
    Passkey(String),
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

    pub fn is_storage_error(&self) -> bool {
        matches!(self, Error::Storage(_))
    }

    pub fn is_session_error(&self) -> bool {
        matches!(self, Error::Session(_))
    }

    pub fn is_crypto_error(&self) -> bool {
        matches!(self, Error::Crypto(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let auth_error = Error::Auth(AuthError::InvalidCredentials);
        assert_eq!(
            auth_error.to_string(),
            "Authentication error: Invalid credentials"
        );

        let validation_error =
            Error::Validation(ValidationError::InvalidEmail("test@".to_string()));
        assert_eq!(
            validation_error.to_string(),
            "Validation error: Invalid email format: test@"
        );

        let storage_error = Error::Storage(StorageError::NotFound);
        assert_eq!(storage_error.to_string(), "Storage error: Record not found");
    }

    #[test]
    fn test_auth_error_variants() {
        let invalid_creds = AuthError::InvalidCredentials;
        assert_eq!(invalid_creds.to_string(), "Invalid credentials");

        let user_not_found = AuthError::UserNotFound;
        assert_eq!(user_not_found.to_string(), "User not found");

        let user_exists = AuthError::UserAlreadyExists;
        assert_eq!(user_exists.to_string(), "User already exists");

        let unsupported = AuthError::UnsupportedMethod("WebAuthn".to_string());
        assert_eq!(
            unsupported.to_string(),
            "Unsupported authentication method: WebAuthn"
        );
    }

    #[test]
    fn test_is_auth_error() {
        assert!(Error::Auth(AuthError::InvalidCredentials).is_auth_error());
        assert!(Error::Auth(AuthError::UserNotFound).is_auth_error());
        assert!(Error::Auth(AuthError::UserAlreadyExists).is_auth_error());
        assert!(!Error::Auth(AuthError::EmailNotVerified).is_auth_error());
        assert!(!Error::Storage(StorageError::NotFound).is_auth_error());
    }

    #[test]
    fn test_is_validation_error() {
        assert!(
            Error::Validation(ValidationError::InvalidEmail("test".to_string()))
                .is_validation_error()
        );
        assert!(Error::Validation(ValidationError::WeakPassword).is_validation_error());
        assert!(
            Error::Validation(ValidationError::InvalidField("name".to_string()))
                .is_validation_error()
        );
        assert!(
            Error::Validation(ValidationError::MissingField("email".to_string()))
                .is_validation_error()
        );
        assert!(!Error::Auth(AuthError::InvalidCredentials).is_validation_error());
    }

    #[test]
    fn test_session_error_variants() {
        let not_found = SessionError::NotFound;
        assert_eq!(not_found.to_string(), "Session not found");

        let expired = SessionError::Expired;
        assert_eq!(expired.to_string(), "Session expired");

        let invalid_token = SessionError::InvalidToken("malformed".to_string());
        assert_eq!(invalid_token.to_string(), "Invalid token: malformed");
    }

    #[test]
    fn test_storage_error_variants() {
        let db_error = StorageError::Database("connection failed".to_string());
        assert_eq!(db_error.to_string(), "Database error: connection failed");

        let not_found = StorageError::NotFound;
        assert_eq!(not_found.to_string(), "Record not found");
    }

    #[test]
    fn test_validation_error_variants() {
        let invalid_email = ValidationError::InvalidEmail("bad@".to_string());
        assert_eq!(invalid_email.to_string(), "Invalid email format: bad@");

        let weak_password = ValidationError::WeakPassword;
        assert_eq!(weak_password.to_string(), "Weak password");

        let missing_field = ValidationError::MissingField("username".to_string());
        assert_eq!(
            missing_field.to_string(),
            "Missing required field: username"
        );
    }

    #[test]
    fn test_event_error_variants() {
        let bus_error = EventError::BusError("dispatcher failed".to_string());
        assert_eq!(bus_error.to_string(), "Event bus error: dispatcher failed");

        let handler_error = EventError::HandlerError("timeout".to_string());
        assert_eq!(handler_error.to_string(), "Event handler error: timeout");
    }

    #[test]
    fn test_error_from_conversions() {
        let auth_error = AuthError::InvalidCredentials;
        let error: Error = auth_error.into();
        assert!(matches!(error, Error::Auth(AuthError::InvalidCredentials)));

        let validation_error = ValidationError::WeakPassword;
        let error: Error = validation_error.into();
        assert!(matches!(
            error,
            Error::Validation(ValidationError::WeakPassword)
        ));
    }
}
