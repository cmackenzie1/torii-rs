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
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|_| StorageError::Database("Failed to set password hash".to_string()))?;
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
            .map_err(|_| StorageError::Database("Failed to get password hash".to_string()))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PostgresStorage;
    use sqlx::PgPool;

    use tokio::sync::OnceCell;
    use torii_core::UserId;

    static TEST_POOL: OnceCell<PgPool> = OnceCell::const_new();

    async fn get_test_pool() -> &'static PgPool {
        TEST_POOL
            .get_or_init(|| async {
                let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
                    "postgres://postgres:postgres@localhost/torii_test".to_string()
                });

                PgPool::connect(&database_url)
                    .await
                    .expect("Failed to connect to test database")
            })
            .await
    }

    async fn setup_test_storage() -> PostgresStorage {
        let pool = get_test_pool().await.clone();

        // Create test user table if it doesn't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                password_hash TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
        "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create test table");

        PostgresStorage::new(pool)
    }

    async fn cleanup_test_user(storage: &PostgresStorage, user_id: &UserId) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id.as_str())
            .execute(&storage.pool)
            .await;
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_set_and_get_password_hash() {
        let storage = setup_test_storage().await;
        let user_id = UserId::new_random();
        let password_hash = "hashed_password_123";

        // First insert a test user
        sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
            .bind(user_id.as_str())
            .bind("test@example.com")
            .execute(&storage.pool)
            .await
            .expect("Failed to insert test user");

        // Test setting password hash
        let result = storage.set_password_hash(&user_id, password_hash).await;
        assert!(result.is_ok());

        // Test getting password hash
        let result = storage.get_password_hash(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(password_hash.to_string()));

        // Cleanup
        cleanup_test_user(&storage, &user_id).await;
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_get_password_hash_not_found() {
        let storage = setup_test_storage().await;
        let user_id = UserId::new_random();

        let result = storage.get_password_hash(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_set_password_hash_nonexistent_user() {
        let storage = setup_test_storage().await;
        let user_id = UserId::new_random();
        let password_hash = "hashed_password_123";

        let result = storage.set_password_hash(&user_id, password_hash).await;
        // Should succeed but not actually update anything
        assert!(result.is_ok());
    }
}
