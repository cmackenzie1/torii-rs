use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, UserId,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose, TokenStorage},
};

/// SeaORM implementation of TokenRepository
pub struct SeaORMTokenRepository {
    storage: SeaORMStorage,
}

impl SeaORMTokenRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }

    /// Generate a cryptographically secure random token
    fn generate_token() -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }
}

#[async_trait]
impl TokenRepository for SeaORMTokenRepository {
    async fn create_token(
        &self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        let token_string = Self::generate_token();
        let now = Utc::now();
        let expires_at = now + expires_in;

        let secure_token = SecureToken::new(
            user_id.clone(),
            token_string,
            purpose,
            None, // not used yet
            expires_at,
            now,
            now,
        );

        self.storage
            .save_secure_token(&secure_token)
            .await
            .map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

        Ok(secure_token)
    }

    async fn verify_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        let token_result = self.storage.get_secure_token(token, purpose).await?;

        if let Some(secure_token) = token_result {
            // Mark token as used
            self.storage.set_secure_token_used(token, purpose).await?;

            // Update the token's used_at field for the return value
            let mut updated_token = secure_token;
            updated_token.used_at = Some(Utc::now());
            updated_token.updated_at = Utc::now();

            Ok(Some(updated_token))
        } else {
            Ok(None)
        }
    }

    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        let token_result = self.storage.get_secure_token(token, purpose).await?;

        if let Some(secure_token) = token_result {
            // Check if token is valid (not expired and not used)
            let now = Utc::now();
            Ok(secure_token.expires_at > now && secure_token.used_at.is_none())
        } else {
            Ok(false)
        }
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.storage.cleanup_expired_secure_tokens().await
    }
}
