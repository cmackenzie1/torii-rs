use async_trait::async_trait;
use sqlx::SqlitePool;
use torii_core::{
    Error,
    error::StorageError,
    storage::MagicToken,
    repositories::MagicLinkRepository,
};
use chrono::Duration;

pub struct SqliteMagicLinkRepository {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl SqliteMagicLinkRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MagicLinkRepository for SqliteMagicLinkRepository {
    async fn create_token(&self, _email: &str, _expires_in: Duration) -> Result<MagicToken, Error> {
        Err(Error::Storage(StorageError::Database("Magic link repository not yet implemented".to_string())))
    }

    async fn verify_token(&self, _token: &str) -> Result<Option<String>, Error> {
        Err(Error::Storage(StorageError::Database("Magic link repository not yet implemented".to_string())))
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database("Magic link repository not yet implemented".to_string())))
    }
}