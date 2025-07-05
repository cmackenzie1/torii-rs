use async_trait::async_trait;
use sqlx::SqlitePool;
use torii_core::{Error, UserId, error::StorageError, repositories::PasswordRepository};

pub struct SqlitePasswordRepository {
    pool: SqlitePool,
}

impl SqlitePasswordRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordRepository for SqlitePasswordRepository {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = ?1 WHERE id = ?2")
            .bind(hash)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        let result =
            sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = ?1")
                .bind(user_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(result)
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = NULL WHERE id = ?1")
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }
}
