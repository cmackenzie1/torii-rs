use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use std::str::FromStr;
use torii_core::{
    Error, UserId,
    crypto::hash_token,
    error::StorageError,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose},
};

use crate::SeaORMStorageError;
use crate::entities::secure_token;

/// SeaORM implementation of TokenRepository
pub struct SeaORMTokenRepository {
    pool: DatabaseConnection,
}

impl SeaORMTokenRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
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

        // Create the active model for insertion
        let model = secure_token::ActiveModel {
            user_id: Set(user_id.to_string()),
            token: Set(token_hash.clone()), // Store hash, not plaintext
            purpose: Set(purpose.as_str().to_string()),
            used_at: Set(None),
            expires_at: Set(expires_at),
            created_at: Set(now),
            updated_at: Set(now),
            ..Default::default()
        };

        let result = model
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        // Return SecureToken with plaintext token (for the caller) and hash (stored)
        Ok(SecureToken::new(
            user_id.clone(),
            token_string, // Plaintext returned to user
            token_hash,   // Hash stored in database
            purpose,
            None, // not used yet
            result.expires_at,
            result.created_at,
            result.updated_at,
        ))
    }

    async fn verify_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        // Compute the hash of the provided token
        let token_hash = hash_token(token);
        let now = Utc::now();

        // Query the specific token by its hash
        let result = secure_token::Entity::find()
            .filter(secure_token::Column::Token.eq(&token_hash))
            .filter(secure_token::Column::Purpose.eq(purpose.as_str()))
            .filter(secure_token::Column::ExpiresAt.gt(now))
            .filter(secure_token::Column::UsedAt.is_null())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(row) = result {
            let user_id = UserId::new(&row.user_id);
            let stored_purpose = TokenPurpose::from_str(&row.purpose).map_err(|e| {
                Error::Storage(StorageError::Database(format!(
                    "Invalid purpose in database: {}",
                    e
                )))
            })?;

            // Use from_storage since we only have the hash, not the plaintext
            let secure_token = SecureToken::from_storage(
                user_id,
                row.token.clone(), // This is the hash stored in the 'token' column
                stored_purpose,
                row.used_at,
                row.expires_at,
                row.created_at,
                row.updated_at,
            );

            // Double-check using constant-time comparison
            if secure_token.verify(token) {
                // Mark token as used
                let mut active_model: secure_token::ActiveModel = row.into();
                active_model.used_at = Set(Some(now));
                active_model.updated_at = Set(now);

                active_model
                    .update(&self.pool)
                    .await
                    .map_err(SeaORMStorageError::Database)?;

                // Update the token's used_at field for the return value
                let mut updated_token = secure_token;
                updated_token.used_at = Some(now);
                updated_token.updated_at = now;

                return Ok(Some(updated_token));
            }
        }

        Ok(None)
    }

    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        // Compute the hash of the provided token
        let token_hash = hash_token(token);
        let now = Utc::now();

        // Query the specific token by its hash
        let result = secure_token::Entity::find()
            .filter(secure_token::Column::Token.eq(&token_hash))
            .filter(secure_token::Column::Purpose.eq(purpose.as_str()))
            .filter(secure_token::Column::ExpiresAt.gt(now))
            .filter(secure_token::Column::UsedAt.is_null())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(row) = result {
            let stored_purpose = TokenPurpose::from_str(&row.purpose).map_err(|e| {
                Error::Storage(StorageError::Database(format!(
                    "Invalid purpose in database: {}",
                    e
                )))
            })?;

            let secure_token = SecureToken::from_storage(
                UserId::new(&row.user_id),
                row.token,
                stored_purpose,
                row.used_at,
                row.expires_at,
                row.created_at,
                row.updated_at,
            );

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
        let now = Utc::now();

        secure_token::Entity::delete_many()
            .filter(secure_token::Column::ExpiresAt.lt(now))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::repositories::SeaORMUserRepository;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    async fn create_test_user(pool: &DatabaseConnection) -> UserId {
        let repo = SeaORMUserRepository::new(pool.clone());
        let user = repo
            .create_user("test@example.com", Some("Test User"))
            .await
            .unwrap();
        user.id
    }

    #[tokio::test]
    async fn test_create_and_verify_token() {
        let pool = setup_test_db().await;
        let repo = SeaORMTokenRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let token = repo
            .create_token(&user_id, TokenPurpose::PasswordReset, Duration::hours(1))
            .await
            .unwrap();

        assert_eq!(token.user_id, user_id);
        assert!(token.used_at.is_none());

        // Verify the token using the plaintext
        let verified = repo
            .verify_token(token.token().unwrap(), TokenPurpose::PasswordReset)
            .await
            .unwrap();

        assert!(verified.is_some());
        let verified = verified.unwrap();
        assert!(verified.used_at.is_some());
    }

    #[tokio::test]
    async fn test_check_token() {
        let pool = setup_test_db().await;
        let repo = SeaORMTokenRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let token = repo
            .create_token(
                &user_id,
                TokenPurpose::EmailVerification,
                Duration::hours(1),
            )
            .await
            .unwrap();

        // Check the token is valid
        let is_valid = repo
            .check_token(token.token().unwrap(), TokenPurpose::EmailVerification)
            .await
            .unwrap();

        assert!(is_valid);

        // Check with wrong purpose
        let is_valid = repo
            .check_token(token.token().unwrap(), TokenPurpose::PasswordReset)
            .await
            .unwrap();

        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_token_cannot_be_reused() {
        let pool = setup_test_db().await;
        let repo = SeaORMTokenRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let token = repo
            .create_token(&user_id, TokenPurpose::PasswordReset, Duration::hours(1))
            .await
            .unwrap();

        // First verification should succeed
        let verified = repo
            .verify_token(token.token().unwrap(), TokenPurpose::PasswordReset)
            .await
            .unwrap();
        assert!(verified.is_some());

        // Second verification should fail (token already used)
        let verified = repo
            .verify_token(token.token().unwrap(), TokenPurpose::PasswordReset)
            .await
            .unwrap();
        assert!(verified.is_none());
    }
}
