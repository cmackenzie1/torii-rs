use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use derive_builder::Builder;
use sqlx::Row;
use sqlx::SqlitePool;
use std::time::Duration;
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

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        let migrations = sqlx::migrate!("./migrations");
        tracing::debug!("Applying migrations: {:?}", migrations);
        migrations.run(&self.pool).await?;
        tracing::debug!("Applied latest migrations");
        Ok(())
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
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create user");
                Self::Error::Storage("Failed to create user".to_string())
            })?;

        let user = self.get_user(user.id.as_ref()).await?;
        if let Some(user) = user {
            Ok(user)
        } else {
            Err(Self::Error::Storage("Failed to create user".to_string()))
        }
    }

    async fn get_user(&self, id: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user");
            Self::Error::Storage("Failed to get user".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, User>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by email");
            Self::Error::Storage("Failed to get user by email".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
        let user = self.get_user_by_email(email).await?;
        if let Some(user) = user {
            return Ok(user);
        }

        let user = self
            .create_user(
                &NewUser::builder()
                    .id(UserId::new_random())
                    .email(email.to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get or create user by email");
                Self::Error::Storage("Failed to get or create user by email".to_string())
            })?;

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
        .bind(user.email_verified_at)
        .bind(user.updated_at)
        .bind(&user.id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            Self::Error::Storage("Failed to update user".to_string())
        })?;

        let user = self.get_user(user.id.as_ref()).await?;
        if let Some(user) = user {
            Ok(user)
        } else {
            Err(Self::Error::Storage("Failed to update user".to_string()))
        }
    }

    async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                Self::Error::Storage("Failed to delete user".to_string())
            })?;

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
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to set password hash");
                <Self as EmailAuthStorage>::Error::Storage(
                    "Failed to set password hash".to_string(),
                )
            })?;

        Ok(())
    }

    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<String, <Self as EmailAuthStorage>::Error> {
        let hash = sqlx::query("SELECT password_hash FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get password hash");
                <Self as EmailAuthStorage>::Error::Storage(
                    "Failed to get password hash".to_string(),
                )
            })?;

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
            .bind(session.created_at)
            .bind(session.updated_at)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|_| Self::Error::Storage("Failed to create session".to_string()))?;

        Ok(self.get_session(session.id.as_ref()).await?)
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
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get session");
            Self::Error::Storage("Failed to get session".to_string())
        })?;

        Ok(session)
    }

    async fn delete_session(&self, id: &str) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete session");
                Self::Error::Storage("Failed to delete session".to_string())
            })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow, Builder)]
#[builder(pattern = "owned")]
pub struct OIDCAccount {
    pub user_id: String,
    pub provider: String,
    pub subject: String,
    #[builder(default = "Utc::now()")]
    pub created_at: DateTime<Utc>,
    #[builder(default = "Utc::now()")]
    pub updated_at: DateTime<Utc>,
}

impl OIDCAccount {
    pub fn new(
        user_id: impl Into<String>,
        provider: impl Into<String>,
        subject: impl Into<String>,
    ) -> Self {
        OIDCAccountBuilder::default()
            .user_id(user_id.into())
            .provider(provider.into())
            .subject(subject.into())
            .build()
            .expect("Default builder should never fail")
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        Utc::now() > self.created_at + ttl
    }
}

#[async_trait]
pub trait OIDCStorage: UserStorage + SessionStorage {
    type Error: std::error::Error + Send + Sync;

    async fn create_oidc_account(
        &self,
        oidc_account: &OIDCAccount,
    ) -> Result<OIDCAccount, <Self as OIDCStorage>::Error>;

    async fn get_nonce(&self, id: &str) -> Result<Option<String>, <Self as OIDCStorage>::Error>;
    async fn save_nonce(
        &self,
        id: &str,
        value: &str,
        expires_at: &DateTime<Utc>,
    ) -> Result<(), <Self as OIDCStorage>::Error>;

    async fn get_oidc_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OIDCAccount>, <Self as OIDCStorage>::Error>;
}

#[async_trait]
impl OIDCStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_oidc_account(
        &self,
        oidc_account: &OIDCAccount,
    ) -> Result<OIDCAccount, <Self as OIDCStorage>::Error> {
        sqlx::query("INSERT INTO oidc_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(&oidc_account.user_id)
            .bind(&oidc_account.provider)
            .bind(&oidc_account.subject)
            .bind(oidc_account.created_at)
            .bind(oidc_account.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create oidc account");
                <Self as OIDCStorage>::Error::Storage(
                    "Failed to create oidc account".to_string(),
                )
            })?;

        let oidc_account = sqlx::query_as::<_, OIDCAccount>(
            r#"
            SELECT user_id, provider, subject, created_at, updated_at
            FROM oidc_accounts
            WHERE user_id = ?
            "#,
        )
        .bind(&oidc_account.user_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oidc account");
            <Self as OIDCStorage>::Error::Storage("Failed to get oidc account".to_string())
        })?;

        Ok(oidc_account)
    }

    async fn get_nonce(&self, id: &str) -> Result<Option<String>, <Self as OIDCStorage>::Error> {
        let nonce = sqlx::query("SELECT value FROM nonces WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get nonce");
                <Self as OIDCStorage>::Error::Storage("Failed to get nonce".to_string())
            })?;

        if let Some(nonce) = nonce {
            Ok(Some(nonce.get("value")))
        } else {
            Ok(None)
        }
    }

    async fn save_nonce(
        &self,
        id: &str,
        value: &str,
        expires_at: &DateTime<Utc>,
    ) -> Result<(), <Self as OIDCStorage>::Error> {
        sqlx::query("INSERT INTO nonces (id, value, expires_at) VALUES (?, ?, ?)")
            .bind(id)
            .bind(value)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to save nonce");
                <Self as OIDCStorage>::Error::Storage("Failed to save nonce".to_string())
            })?;

        Ok(())
    }

    async fn get_oidc_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OIDCAccount>, <Self as OIDCStorage>::Error> {
        let oidc_account = sqlx::query_as::<_, OIDCAccount>(
            r#"
            SELECT user_id, provider, subject, created_at, updated_at
            FROM oidc_accounts
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oidc account");
            <Self as OIDCStorage>::Error::Storage("Failed to get oidc account".to_string())
        })?;

        if let Some(oidc_account) = oidc_account {
            Ok(Some(oidc_account))
        } else {
            Ok(None)
        }
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
            .create_user(
                &NewUser::builder()
                    .id(UserId::new("1"))
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let user = storage.get_user(&"1").await.unwrap().unwrap();
        assert_eq!(user.email, "test@example.com");

        storage.delete_user(&"1").await.unwrap();
        let user = storage.get_user(&"1").await.unwrap();
        assert!(user.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_session_storage() {
        let storage = setup_sqlite_storage().await.unwrap();
        storage
            .create_user(
                &NewUser::builder()
                    .id(UserId::new("1"))
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        storage
            .create_session(
                &Session::builder()
                    .id(SessionId::new("1"))
                    .user_id(UserId::new("1"))
                    .user_agent(Some("test".to_string()))
                    .ip_address(Some("127.0.0.1".to_string()))
                    .created_at(Utc::now())
                    .updated_at(Utc::now())
                    .expires_at(Utc::now() + Duration::from_secs(1000))
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let session = storage.get_session(&"1").await.unwrap();
        assert_eq!(session.user_id, UserId::new("1"));

        storage.delete_session(&"1").await.unwrap();
        let session = storage.get_session(&"1").await;
        assert!(session.is_err());
    }
}
