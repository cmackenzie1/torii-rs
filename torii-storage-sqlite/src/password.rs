use crate::SqliteStorage;
use async_trait::async_trait;
use torii_core::UserId;
use torii_core::error::StorageError;
use torii_core::storage::PasswordStorage;

#[async_trait]
impl PasswordStorage for SqliteStorage {
    async fn set_password_hash(
        &self,
        user_id: &UserId,
        hash: &str,
    ) -> Result<(), torii_core::Error> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<Option<String>, torii_core::Error> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{create_test_user, setup_sqlite_storage};

    #[tokio::test]
    async fn test_password_hash() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Set password hash
        let hash = "test_hash_123";
        storage
            .set_password_hash(&user.id, hash)
            .await
            .expect("Failed to set password hash");

        // Get password hash
        let stored_hash = storage
            .get_password_hash(&user.id)
            .await
            .expect("Failed to get password hash");

        assert_eq!(stored_hash, Some(hash.to_string()));

        // Get password hash for non-existent user
        let non_existent = storage
            .get_password_hash(&UserId::new("non_existent"))
            .await
            .expect("Failed to get password hash");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_password_hash_update() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user with initial password hash
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        let initial_hash = "initial_hash_123";
        storage
            .set_password_hash(&user.id, initial_hash)
            .await
            .expect("Failed to set initial password hash");

        // Set updated password hash
        let updated_hash = "updated_hash_456";
        storage
            .set_password_hash(&user.id, updated_hash)
            .await
            .expect("Failed to set updated password hash");

        // Get updated password hash
        let stored_hash = storage
            .get_password_hash(&user.id)
            .await
            .expect("Failed to get updated password hash");

        assert_eq!(stored_hash, Some(updated_hash.to_string()));
    }
}
