use crate::SqliteUser;
use async_trait::async_trait;
use sqlx::SqlitePool;
use torii_core::{
    Error, User, UserId, error::StorageError, repositories::UserRepository, storage::NewUser,
};

pub struct SqliteUserRepository {
    pool: SqlitePool,
}

impl SqliteUserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        let now = chrono::Utc::now().timestamp();
        let email_verified_timestamp = user.email_verified_at.map(|dt| dt.timestamp());

        let sqlite_user = sqlx::query_as::<_, SqliteUser>(
            r#"
            INSERT INTO users (id, email, name, email_verified_at, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING *
            "#,
        )
        .bind(user.id.as_str())
        .bind(&user.email)
        .bind(&user.name)
        .bind(email_verified_timestamp)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_user.into())
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        let sqlite_user = sqlx::query_as::<_, SqliteUser>("SELECT * FROM users WHERE id = ?1")
            .bind(id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_user.map(|u| u.into()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let sqlite_user = sqlx::query_as::<_, SqliteUser>("SELECT * FROM users WHERE email = ?1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_user.map(|u| u.into()))
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        if let Some(user) = self.find_by_email(email).await? {
            Ok(user)
        } else {
            let new_user = NewUser::new(email.to_string());
            self.create(new_user).await
        }
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        let now = chrono::Utc::now().timestamp();
        let email_verified_timestamp = user.email_verified_at.map(|dt| dt.timestamp());

        let sqlite_user = sqlx::query_as::<_, SqliteUser>(
            r#"
            UPDATE users 
            SET email = ?2, name = ?3, email_verified_at = ?4, updated_at = ?5
            WHERE id = ?1
            RETURNING *
            "#,
        )
        .bind(user.id.as_str())
        .bind(&user.email)
        .bind(&user.name)
        .bind(email_verified_timestamp)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_user.into())
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query("UPDATE users SET email_verified_at = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(now)
            .bind(now)
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }
}
