//! PostgreSQL implementation of the token repository.

use async_trait::async_trait;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::{TryRngCore, rngs::OsRng};
use sqlx::PgPool;
use std::str::FromStr;
use torii_core::{
    Error, UserId,
    crypto::hash_token,
    error::StorageError,
    repositories::TokenRepository,
    storage::{SecureToken, TokenPurpose},
};

/// PostgreSQL repository for secure tokens.
pub struct PostgresTokenRepository {
    pool: PgPool,
}

impl PostgresTokenRepository {
    /// Create a new PostgreSQL token repository.
    pub fn new(pool: PgPool) -> Self {
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

#[derive(Debug, sqlx::FromRow)]
struct SecureTokenRow {
    user_id: String,
    token: String, // This is the hash, not plaintext
    purpose: String,
    used_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl TokenRepository for PostgresTokenRepository {
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
            token_string,       // Plaintext returned to user
            token_hash.clone(), // Hash stored in database
            purpose,
            None, // not used yet
            expires_at,
            now,
            now,
        );

        // Store the token_hash in the 'token' column (never store plaintext)
        sqlx::query(
            r#"
            INSERT INTO secure_tokens (user_id, token, purpose, used_at, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(secure_token.user_id.as_str())
        .bind(&secure_token.token_hash) // Store hash, not plaintext
        .bind(secure_token.purpose.as_str())
        .bind(secure_token.used_at)
        .bind(secure_token.expires_at)
        .bind(secure_token.created_at)
        .bind(secure_token.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create secure token");
            Error::Storage(StorageError::Database(
                "Failed to create secure token".to_string(),
            ))
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
        let now = Utc::now();

        // Query the specific token by its hash
        let result = sqlx::query_as::<_, SecureTokenRow>(
            r#"
            SELECT user_id, token, purpose, used_at, expires_at, created_at, updated_at
            FROM secure_tokens
            WHERE token = $1 AND purpose = $2 AND expires_at > $3 AND used_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .bind(purpose.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to verify token");
            Error::Storage(StorageError::Database("Failed to verify token".to_string()))
        })?;

        if let Some(row) = result {
            let user_id = UserId::new(&row.user_id);
            let stored_purpose = TokenPurpose::from_str(&row.purpose).map_err(|e| {
                tracing::error!(error = %e, "Invalid purpose in database");
                e
            })?;

            // Use from_storage since we only have the hash, not the plaintext
            let secure_token = SecureToken::from_storage(
                user_id,
                row.token, // This is the hash stored in the 'token' column
                stored_purpose,
                row.used_at,
                row.expires_at,
                row.created_at,
                row.updated_at,
            );

            // Double-check using constant-time comparison
            if secure_token.verify(token) {
                // Mark token as used
                sqlx::query(
                    "UPDATE secure_tokens SET used_at = $1, updated_at = $2 WHERE token = $3 AND purpose = $4",
                )
                .bind(now)
                .bind(now)
                .bind(&token_hash)
                .bind(purpose.as_str())
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to mark token as used");
                    Error::Storage(StorageError::Database(
                        "Failed to mark token as used".to_string(),
                    ))
                })?;

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
        let result = sqlx::query_as::<_, SecureTokenRow>(
            r#"
            SELECT user_id, token, purpose, used_at, expires_at, created_at, updated_at
            FROM secure_tokens
            WHERE token = $1 AND purpose = $2 AND expires_at > $3 AND used_at IS NULL
            "#,
        )
        .bind(&token_hash)
        .bind(purpose.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to check token");
            Error::Storage(StorageError::Database("Failed to check token".to_string()))
        })?;

        if let Some(row) = result {
            let stored_purpose = TokenPurpose::from_str(&row.purpose).map_err(|e| {
                tracing::error!(error = %e, "Invalid purpose in database");
                e
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

        sqlx::query("DELETE FROM secure_tokens WHERE expires_at < $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to cleanup expired tokens");
                Error::Storage(StorageError::Database(
                    "Failed to cleanup expired tokens".to_string(),
                ))
            })?;

        Ok(())
    }
}
