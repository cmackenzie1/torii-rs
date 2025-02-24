use crate::SqliteStorage;
use async_trait::async_trait;
use torii_core::UserId;
use torii_core::error::StorageError;
use torii_core::storage::EmailPasswordStorage;

#[async_trait]
impl EmailPasswordStorage for SqliteStorage {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), StorageError> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(user_id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, StorageError> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(result)
    }
}
