//! PostgreSQL implementation of the password repository.

use async_trait::async_trait;
use sqlx::PgPool;
use torii_core::{Error, UserId, error::StorageError, repositories::PasswordRepository};

/// PostgreSQL repository for password data.
pub struct PostgresPasswordRepository {
    pool: PgPool,
}

impl PostgresPasswordRepository {
    /// Create a new PostgreSQL password repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordRepository for PostgresPasswordRepository {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        let result = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to set password hash");
                Error::Storage(StorageError::Database(
                    "Failed to set password hash".to_string(),
                ))
            })?;

        if result.rows_affected() == 0 {
            return Err(Error::Storage(StorageError::NotFound));
        }

        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get password hash");
                Error::Storage(StorageError::Database(
                    "Failed to get password hash".to_string(),
                ))
            })?;

        Ok(result)
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        let result = sqlx::query("UPDATE users SET password_hash = NULL WHERE id = $1")
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to remove password hash");
                Error::Storage(StorageError::Database(
                    "Failed to remove password hash".to_string(),
                ))
            })?;

        if result.rows_affected() == 0 {
            return Err(Error::Storage(StorageError::NotFound));
        }

        Ok(())
    }
}
