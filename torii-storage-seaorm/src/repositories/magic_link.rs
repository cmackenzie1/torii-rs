use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    storage::MagicToken, Error,
    repositories::MagicLinkRepository,
};
use crate::SeaORMStorage;
use chrono::Duration;

pub struct SeaORMMagicLinkRepository {
    storage: SeaORMStorage,
}

impl SeaORMMagicLinkRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl MagicLinkRepository for SeaORMMagicLinkRepository {
    async fn create_token(&self, email: &str, expires_in: Duration) -> Result<MagicToken, Error> {
        self.storage.create_magic_token(email, expires_in).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn verify_token(&self, token: &str) -> Result<Option<String>, Error> {
        self.storage.verify_magic_token(token).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.storage.cleanup_expired_magic_tokens().await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}