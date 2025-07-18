use async_trait::async_trait;
use chrono::Duration;
use torii_core::{
    Error, UserId,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose},
};

/// Stub SQLite implementation of TokenRepository
/// TODO: Implement this properly
pub struct SqliteTokenRepository;

impl SqliteTokenRepository {
    pub fn new(_pool: sqlx::SqlitePool) -> Self {
        Self
    }
}

#[async_trait]
impl TokenRepository for SqliteTokenRepository {
    async fn create_token(
        &self,
        _user_id: &UserId,
        _purpose: TokenPurpose,
        _expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        Err(Error::Storage(torii_core::error::StorageError::Database(
            "SQLite token repository not yet implemented".to_string(),
        )))
    }

    async fn verify_token(
        &self,
        _token: &str,
        _purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        Err(Error::Storage(torii_core::error::StorageError::Database(
            "SQLite token repository not yet implemented".to_string(),
        )))
    }

    async fn check_token(&self, _token: &str, _purpose: TokenPurpose) -> Result<bool, Error> {
        Err(Error::Storage(torii_core::error::StorageError::Database(
            "SQLite token repository not yet implemented".to_string(),
        )))
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        Ok(()) // No-op for now
    }
}
