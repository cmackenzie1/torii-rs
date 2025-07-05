use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::Duration;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error,
    repositories::MagicLinkRepository,
    storage::{MagicLinkStorage, MagicToken},
};

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
    async fn create_token(&self, _email: &str, expires_in: Duration) -> Result<MagicToken, Error> {
        use chrono::Utc;
        use torii_core::UserId;
        use uuid::Uuid;

        // Generate a random token
        let token = Uuid::new_v4().to_string();

        // Create magic token
        let magic_token = MagicToken::new(
            UserId::default(), // This should be looked up by email
            token,
            None,
            Utc::now() + expires_in,
            Utc::now(),
            Utc::now(),
        );

        self.storage
            .save_magic_token(&magic_token)
            .await
            .map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

        Ok(magic_token)
    }

    async fn verify_token(&self, token: &str) -> Result<Option<String>, Error> {
        let magic_token = self.storage.get_magic_token(token).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        if let Some(token) = magic_token {
            if !token.used() {
                // Mark token as used
                self.storage
                    .set_magic_token_used(&token.token)
                    .await
                    .map_err(|e| {
                        Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                    })?;

                // Return the user ID or email associated with the token
                Ok(Some(token.user_id.to_string()))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        // The current MagicLinkStorage trait doesn't have this method, so this is a placeholder
        // In a real implementation, you would clean up expired tokens
        Ok(())
    }
}
