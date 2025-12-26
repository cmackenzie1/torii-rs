use crate::SeaORMStorage;
use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, UserId,
    crypto::hash_token,
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

    /// Generate a cryptographically secure random token with 256 bits of entropy
    fn generate_token() -> String {
        let mut bytes = [0u8; 32]; // 256 bits of entropy
        OsRng
            .try_fill_bytes(&mut bytes)
            .expect("Failed to generate random bytes - system RNG unavailable");
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
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
        let token_hash = hash_token(&token_string);
        let now = Utc::now();
        let expires_at = now + expires_in;

        let secure_token = SecureToken::new(
            user_id.clone(),
            token_string, // Plaintext returned to user
            token_hash,   // Hash stored in database
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
        // Compute the hash of the provided token
        let token_hash = hash_token(token);

        // Look up the token by hash - no iteration needed
        let stored_token = self.storage.get_token_by_hash(&token_hash, purpose).await?;

        if let Some(secure_token) = stored_token {
            // Double-check using constant-time comparison
            // This is technically redundant since we looked up by hash,
            // but provides defense in depth
            if secure_token.verify(token) {
                // Mark token as used
                self.storage
                    .set_secure_token_used_by_hash(&secure_token.token_hash, purpose)
                    .await?;

                // Update the token's used_at field for the return value
                let mut updated_token = secure_token;
                updated_token.used_at = Some(Utc::now());
                updated_token.updated_at = Utc::now();

                return Ok(Some(updated_token));
            }
        }

        Ok(None)
    }

    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        // Compute the hash of the provided token
        let token_hash = hash_token(token);

        // Look up the token by hash - no iteration needed
        let stored_token = self.storage.get_token_by_hash(&token_hash, purpose).await?;

        if let Some(secure_token) = stored_token {
            // Double-check using constant-time comparison
            let now = Utc::now();
            if secure_token.verify(token)
                && secure_token.expires_at > now
                && secure_token.used_at.is_none()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.storage.cleanup_expired_secure_tokens().await
    }
}
