//! PostgreSQL implementation of the user repository.

use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use torii_core::{
    Error, User, UserId, error::StorageError, repositories::UserRepository, storage::NewUser,
};

use crate::PostgresUser;

/// PostgreSQL repository for user data.
pub struct PostgresUserRepository {
    pool: PgPool,
}

impl PostgresUserRepository {
    /// Create a new PostgreSQL user repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        let pg_user = sqlx::query_as::<_, PostgresUser>(
            r#"
            INSERT INTO users (id, email, name, email_verified_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, name, email_verified_at, locked_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_str())
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.email_verified_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            Error::Storage(StorageError::Database("Failed to create user".to_string()))
        })?;

        Ok(pg_user.into())
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        let pg_user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id, email, name, email_verified_at, locked_at, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find user by ID");
            Error::Storage(StorageError::Database(
                "Failed to find user by ID".to_string(),
            ))
        })?;

        Ok(pg_user.map(|u| u.into()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let pg_user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id, email, name, email_verified_at, locked_at, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find user by email");
            Error::Storage(StorageError::Database(
                "Failed to find user by email".to_string(),
            ))
        })?;

        Ok(pg_user.map(|u| u.into()))
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        // Note: There is a potential TOCTOU race condition here between find_by_email and create.
        // If two concurrent requests call this method for the same email, both may pass the
        // existence check and attempt to create the user, causing one to fail with a unique
        // constraint violation. This is acceptable for this use case as the caller can retry.
        if let Some(user) = self.find_by_email(email).await? {
            return Ok(user);
        }

        let new_user = NewUser::new(email.to_string());
        self.create(new_user).await
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        let pg_user = sqlx::query_as::<_, PostgresUser>(
            r#"
            UPDATE users
            SET email = $1, name = $2, email_verified_at = $3, locked_at = $4, updated_at = $5
            WHERE id = $6
            RETURNING id, email, name, email_verified_at, locked_at, created_at, updated_at
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.email_verified_at)
        .bind(user.locked_at)
        .bind(Utc::now())
        .bind(user.id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            Error::Storage(StorageError::Database("Failed to update user".to_string()))
        })?;

        Ok(pg_user.into())
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                Error::Storage(StorageError::Database("Failed to delete user".to_string()))
            })?;

        Ok(())
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        let now = Utc::now();
        sqlx::query("UPDATE users SET email_verified_at = $1, updated_at = $2 WHERE id = $3")
            .bind(now)
            .bind(now)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to mark email verified");
                Error::Storage(StorageError::Database(
                    "Failed to mark email verified".to_string(),
                ))
            })?;

        Ok(())
    }
}
