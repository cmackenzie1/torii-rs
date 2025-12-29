//! PostgreSQL implementation of the token repository.

use async_trait::async_trait;
use chrono::Duration;
use sqlx::PgPool;
use torii_core::{
    Error, UserId,
    error::StorageError,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose},
};

/// PostgreSQL repository for secure tokens.
pub struct PostgresTokenRepository {
    #[allow(dead_code)]
    pool: PgPool,
}

impl PostgresTokenRepository {
    /// Create a new PostgreSQL token repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
    async fn create_token(
        &self,
        _user_id: &UserId,
        _purpose: TokenPurpose,
        _expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        Err(Error::Storage(StorageError::Database(
            "Token repository not yet implemented".to_string(),
        )))
    }

    async fn verify_token(
        &self,
        _token: &str,
        _purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Token repository not yet implemented".to_string(),
        )))
    }

    async fn check_token(&self, _token: &str, _purpose: TokenPurpose) -> Result<bool, Error> {
        Err(Error::Storage(StorageError::Database(
            "Token repository not yet implemented".to_string(),
        )))
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        Ok(()) // No-op for now
    }
}
