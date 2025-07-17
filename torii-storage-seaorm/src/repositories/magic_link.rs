use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::Duration;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, UserId,
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
    async fn create_token(
        &self,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<MagicToken, Error> {
        use chrono::Utc;
        use uuid::Uuid;

        // Generate a random token
        let token = Uuid::new_v4().to_string();

        // Create magic token
        let magic_token = MagicToken::new(
            user_id.clone(),
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

    async fn verify_token(&self, token: &str) -> Result<Option<MagicToken>, Error> {
        let magic_token = self.storage.get_magic_token(token).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        if let Some(mut token) = magic_token {
            if !token.used() && token.expires_at > chrono::Utc::now() {
                // Mark token as used
                self.storage
                    .set_magic_token_used(&token.token)
                    .await
                    .map_err(|e| {
                        Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                    })?;

                // Update the token to reflect it has been used
                token.used_at = Some(chrono::Utc::now());
                token.updated_at = chrono::Utc::now();

                Ok(Some(token))
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
