use crate::PostgresStorage;
use async_trait::async_trait;
use torii_core::UserId;
use torii_core::error::StorageError;
use torii_core::storage::PasswordStorage;

#[async_trait]
impl PasswordStorage for PostgresStorage {
    async fn set_password_hash(
        &self,
        user_id: &UserId,
        hash: &str,
    ) -> Result<(), torii_core::Error> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id::text = $2")
            .bind(hash)
            .bind(user_id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|_| StorageError::Database("Failed to set password hash".to_string()))?;
        Ok(())
    }

    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<Option<String>, torii_core::Error> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id::text = $1")
            .bind(user_id.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| StorageError::Database("Failed to get password hash".to_string()))?;
        Ok(result)
    }
}
