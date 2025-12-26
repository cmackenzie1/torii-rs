use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{ConnectionTrait, FromQueryResult, Statement};
use std::str::FromStr;
use torii_core::{
    Error, UserId,
    storage::{SecureToken, TokenPurpose, TokenStorage},
};

#[async_trait]
impl TokenStorage for SeaORMStorage {
    async fn save_secure_token(&self, token: &SecureToken) -> Result<(), Error> {
        // Get the database backend dynamically
        let backend = self.pool.get_database_backend();

        // Store the token_hash in the 'token' column (never store plaintext)
        let query = Statement::from_sql_and_values(
            backend,
            "INSERT INTO secure_tokens (user_id, token, purpose, used_at, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            vec![
                token.user_id.to_string().into(),
                token.token_hash.clone().into(), // Store hash, not plaintext
                token.purpose.as_str().to_string().into(),
                token.used_at.into(),
                token.expires_at.into(),
                token.created_at.into(),
                token.updated_at.into(),
            ],
        );

        self.pool.execute(query).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        Ok(())
    }

    async fn get_token_by_hash(
        &self,
        token_hash: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        // Custom struct to match our query results
        #[derive(Debug, FromQueryResult)]
        struct SecureTokenResult {
            user_id: String,
            token: String, // This is actually the hash
            purpose: String,
            used_at: Option<chrono::DateTime<Utc>>,
            expires_at: chrono::DateTime<Utc>,
            created_at: chrono::DateTime<Utc>,
            updated_at: chrono::DateTime<Utc>,
        }

        let now = Utc::now();
        let backend = self.pool.get_database_backend();

        // Query the specific token by its hash
        let query = Statement::from_sql_and_values(
            backend,
            "SELECT user_id, token, purpose, used_at, expires_at, created_at, updated_at FROM secure_tokens WHERE token = ? AND purpose = ? AND expires_at > ? AND used_at IS NULL",
            vec![token_hash.into(), purpose.as_str().into(), now.into()],
        );

        let result: Option<SecureTokenResult> = SecureTokenResult::find_by_statement(query)
            .one(&self.pool)
            .await
            .map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

        Ok(result.map(|row| {
            let user_id = UserId::new(&row.user_id);
            let purpose =
                TokenPurpose::from_str(&row.purpose).expect("Invalid purpose in database");

            // Use from_storage since we only have the hash, not the plaintext
            SecureToken::from_storage(
                user_id,
                row.token, // This is the hash stored in the 'token' column
                purpose,
                row.used_at,
                row.expires_at,
                row.created_at,
                row.updated_at,
            )
        }))
    }

    async fn set_secure_token_used_by_hash(
        &self,
        token_hash: &str,
        purpose: TokenPurpose,
    ) -> Result<(), Error> {
        let now = Utc::now();
        let backend = self.pool.get_database_backend();

        let query = Statement::from_sql_and_values(
            backend,
            "UPDATE secure_tokens SET used_at = ?, updated_at = ? WHERE token = ? AND purpose = ?",
            vec![
                now.into(),
                now.into(),
                token_hash.into(),
                purpose.as_str().into(),
            ],
        );

        self.pool.execute(query).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        Ok(())
    }

    async fn cleanup_expired_secure_tokens(&self) -> Result<(), Error> {
        let now = Utc::now();
        let backend = self.pool.get_database_backend();

        let query = Statement::from_sql_and_values(
            backend,
            "DELETE FROM secure_tokens WHERE expires_at < ?",
            vec![now.into()],
        );

        self.pool.execute(query).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        Ok(())
    }
}
