use async_trait::async_trait;
use sqlx::Row;
use sqlx::SqlitePool;
use torii_core::{
    storage::{NewUser, SessionStorage, UserStorage},
    Session, User, UserId,
};

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        sqlx::query("INSERT INTO users (id, email) VALUES (?, ?)")
            .bind(&user.id)
            .bind(&user.email)
            .execute(&self.pool)
            .await
            .map_err(|_| Self::Error::Storage("Failed to create user".to_string()))?;

        Ok(self.get_user(&user.id.as_ref()).await?)
    }

    async fn get_user(&self, id: &str) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Self::Error::Storage("Failed to get user".to_string()))?;

        Ok(user)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> Result<User, Self::Error> {
        sqlx::query_as::<_, User>(
            r#"
            UPDATE users 
            SET email = ?, name = ?, email_verified_at = ?, updated_at = ? 
            WHERE id = ?
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(&user.email_verified_at)
        .bind(&user.updated_at)
        .bind(&user.id)
        .fetch_one(&self.pool)
        .await?;

        Ok(self.get_user(&user.id.as_ref()).await?)
    }

    async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

#[async_trait]
pub trait EmailAuthStorage: UserStorage + SessionStorage {
    type Error: std::error::Error + Send + Sync;

    async fn set_password_hash(
        &self,
        user_id: &UserId,
        hash: &str,
    ) -> Result<(), <Self as EmailAuthStorage>::Error>;
    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<String, <Self as EmailAuthStorage>::Error>;
}

#[async_trait]
impl EmailAuthStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn set_password_hash(
        &self,
        user_id: &UserId,
        hash: &str,
    ) -> Result<(), <Self as EmailAuthStorage>::Error> {
        sqlx::query("UPDATE users SET password_hash = ? WHERE id = ?")
            .bind(hash)
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<String, <Self as EmailAuthStorage>::Error> {
        let hash = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

        Ok(hash.get("password_hash"))
    }
}

#[async_trait]
impl SessionStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
        sqlx::query("INSERT INTO sessions (id, user_id, user_agent, ip_address, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(&session.id)
            .bind(&session.user_id)
            .bind(&session.user_agent)
            .bind(&session.ip_address)
            .bind(&session.created_at)
            .bind(&session.updated_at)
            .bind(&session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|_| Self::Error::Storage("Failed to create session".to_string()))?;

        Ok(self.get_session(&session.id.as_ref()).await?)
    }

    async fn get_session(&self, id: &str) -> Result<Session, Self::Error> {
        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT id, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| Self::Error::Storage("Failed to get session".to_string()))?;

        Ok(session)
    }

    async fn delete_session(&self, id: &str) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|_| Self::Error::Storage("Failed to delete session".to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::types::chrono::Utc;
    use torii_core::session::SessionId;

    use super::*;

    async fn setup_sqlite_storage() -> Result<SqliteStorage, sqlx::Error> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(SqliteStorage::new(pool))
    }

    #[tokio::test]
    async fn test_sqlite_storage() {
        let storage = setup_sqlite_storage().await.unwrap();
        storage
            .create_user(&NewUser {
                id: UserId::new("1"),
                email: "test@example.com".to_string(),
            })
            .await
            .unwrap();

        let user = storage.get_user(&"1").await.unwrap();
        assert_eq!(user.email, "test@example.com");

        storage.delete_user(&"1").await.unwrap();
        let user = storage.get_user(&"1").await;
        assert!(user.is_err());
    }

    #[tokio::test]
    async fn test_sqlite_session_storage() {
        let storage = setup_sqlite_storage().await.unwrap();
        storage
            .create_user(&NewUser {
                id: UserId::new("1"),
                email: "test@example.com".to_string(),
            })
            .await
            .unwrap();

        storage
            .create_session(&Session {
                id: SessionId::new("1"),
                user_id: UserId::new("1"),
                user_agent: Some("test".to_string()),
                ip_address: Some("127.0.0.1".to_string()),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                expires_at: Utc::now() + Duration::from_secs(1000),
            })
            .await
            .unwrap();

        let session = storage.get_session(&"1").await.unwrap();
        assert_eq!(session.user_id, UserId::new("1"));

        storage.delete_session(&"1").await.unwrap();
        let session = storage.get_session(&"1").await;
        assert!(session.is_err());
    }
}
