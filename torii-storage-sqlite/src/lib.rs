use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use sqlx::SqlitePool;
use std::time::Duration;
use torii_core::session::SessionId;
use torii_core::storage::{EmailPasswordStorage, OAuthStorage};
use torii_core::user::OAuthAccount;
use torii_core::Error;
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

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<SqliteUser> for User {
    fn from(user: SqliteUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at)
            .created_at(user.created_at)
            .updated_at(user.updated_at)
            .build()
            .unwrap()
    }
}

impl From<User> for SqliteUser {
    fn from(user: User) -> Self {
        SqliteUser {
            id: user.id.into_inner(),
            email: user.email,
            name: user.name,
            email_verified_at: user.email_verified_at,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[async_trait]
impl UserStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        sqlx::query("INSERT INTO users (id, email) VALUES (?, ?)")
            .bind(user.id.as_ref())
            .bind(&user.email)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create user");
                Self::Error::Storage("Failed to create user".to_string())
            })?;

        let user = self.get_user(&user.id).await?;
        if let Some(user) = user {
            Ok(user)
        } else {
            Err(Self::Error::Storage("Failed to create user".to_string()))
        }
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id = ?
            "#,
        )
        .bind(id.as_ref())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user");
            Self::Error::Storage("Failed to get user".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
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
            Ok(Some(user.into()))
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
        sqlx::query_as::<_, SqliteUser>(
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
        .bind(user.id.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            Self::Error::Storage("Failed to update user".to_string())
        })?;

        let user = self.get_user(&user.id).await?;
        if let Some(user) = user {
            Ok(user)
        } else {
            Err(Self::Error::Storage("Failed to update user".to_string()))
        }
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                Self::Error::Storage("Failed to delete user".to_string())
            })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteSession {
    id: String,
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<SqliteSession> for Session {
    fn from(session: SqliteSession) -> Self {
        Session::builder()
            .id(SessionId::new(&session.id))
            .user_id(UserId::new(&session.user_id))
            .user_agent(session.user_agent)
            .ip_address(session.ip_address)
            .created_at(session.created_at)
            .updated_at(session.updated_at)
            .expires_at(session.expires_at)
            .build()
            .unwrap()
    }
}

impl From<Session> for SqliteSession {
    fn from(session: Session) -> Self {
        SqliteSession {
            id: session.id.into_inner(),
            user_id: session.user_id.into_inner(),
            user_agent: session.user_agent,
            ip_address: session.ip_address,
            created_at: session.created_at,
            updated_at: session.updated_at,
            expires_at: session.expires_at,
        }
    }
}

#[async_trait]
impl SessionStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
        sqlx::query("INSERT INTO sessions (id, user_id, user_agent, ip_address, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(session.id.as_ref())
            .bind(session.user_id.as_ref())
            .bind(&session.user_agent)
            .bind(&session.ip_address)
            .bind(session.created_at)
            .bind(session.updated_at)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|_| Self::Error::Storage("Failed to create session".to_string()))?;

        Ok(self.get_session(&session.id).await?.unwrap())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> {
        let session = sqlx::query_as::<_, SqliteSession>(
            r#"
            SELECT id, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE id = ?
            "#,
        )
        .bind(id.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get session");
            Self::Error::Storage("Failed to get session".to_string())
        })?;

        Ok(Some(session.into()))
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete session");
                Self::Error::Storage("Failed to delete session".to_string())
            })?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to cleanup expired sessions");
                Self::Error::Storage("Failed to cleanup expired sessions".to_string())
            })?;

        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete sessions for user");
                Self::Error::Storage("Failed to delete sessions for user".to_string())
            })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteOAuthAccount {
    user_id: String,
    provider: String,
    subject: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SqliteOAuthAccount {
    pub fn builder() -> SqliteOAuthAccountBuilder {
        SqliteOAuthAccountBuilder::default()
    }

    pub fn new(user_id: UserId, provider: impl Into<String>, subject: impl Into<String>) -> Self {
        SqliteOAuthAccountBuilder::default()
            .user_id(user_id)
            .provider(provider.into())
            .subject(subject.into())
            .build()
            .expect("Default builder should never fail")
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        Utc::now() > self.created_at + ttl
    }
}

impl From<SqliteOAuthAccount> for OAuthAccount {
    fn from(oauth_account: SqliteOAuthAccount) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&oauth_account.user_id))
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(oauth_account.created_at)
            .updated_at(oauth_account.updated_at)
            .build()
            .expect("Default builder should never fail")
    }
}

impl From<OAuthAccount> for SqliteOAuthAccount {
    fn from(oauth_account: OAuthAccount) -> Self {
        SqliteOAuthAccount::builder()
            .user_id(oauth_account.user_id)
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(oauth_account.created_at)
            .updated_at(oauth_account.updated_at)
            .build()
            .expect("Default builder should never fail")
    }
}

#[derive(Default)]
pub struct SqliteOAuthAccountBuilder {
    user_id: Option<UserId>,
    provider: Option<String>,
    subject: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl SqliteOAuthAccountBuilder {
    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn build(self) -> Result<SqliteOAuthAccount, Error> {
        Ok(SqliteOAuthAccount {
            user_id: self.user_id.unwrap().into_inner(),
            provider: self.provider.unwrap(),
            subject: self.subject.unwrap(),
            created_at: self.created_at.unwrap_or_default(),
            updated_at: self.updated_at.unwrap_or_default(),
        })
    }
}

#[async_trait]
impl OAuthStorage for SqliteStorage {
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Self::Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user_id.as_ref())
            .bind(provider)
            .bind(subject)
            .bind(Utc::now())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create oauth account");
                Self::Error::Storage(
                    "Failed to create oauth account".to_string(),
                )
            })?;

        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            SELECT user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE user_id = ?
            "#,
        )
        .bind(user_id.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oauth account");
            Self::Error::Storage("Failed to get oauth account".to_string())
        })?;

        Ok(oauth_account.into())
    }

    async fn get_nonce(&self, id: &str) -> Result<Option<String>, Self::Error> {
        let nonce: Option<String> = sqlx::query_scalar("SELECT value FROM nonces WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get nonce");
                Self::Error::Storage("Failed to get nonce".to_string())
            })?;

        Ok(nonce)
    }

    async fn save_nonce(
        &self,
        id: &str,
        value: &str,
        expires_at: &DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        sqlx::query("INSERT INTO nonces (id, value, expires_at) VALUES (?, ?, ?)")
            .bind(id)
            .bind(value)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to save nonce");
                Self::Error::Storage("Failed to save nonce".to_string())
            })?;

        Ok(())
    }

    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Self::Error> {
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            SELECT user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oauth account");
            Self::Error::Storage("Failed to get oauth account".to_string())
        })?;

        if let Some(oauth_account) = oauth_account {
            Ok(Some(oauth_account.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at
            FROM users
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by provider and subject");
            Self::Error::Storage("Failed to get user by provider and subject".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Self::Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user_id.as_ref())
            .bind(provider)
            .bind(subject)
            .bind(Utc::now())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to link oauth account");
                Self::Error::Storage("Failed to link oauth account".to_string())
            })?;

        Ok(())
    }
}

#[async_trait]
impl EmailPasswordStorage for SqliteStorage {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(hash)
            .bind(user_id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(user_id.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(result)
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

    async fn create_test_user(
        storage: &SqliteStorage,
        id: &str,
    ) -> Result<User, torii_core::Error> {
        storage
            .create_user(
                &NewUser::builder()
                    .id(UserId::new(id))
                    .email(format!("test{}@example.com", id))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
    }

    async fn create_test_session(
        storage: &SqliteStorage,
        session_id: &str,
        user_id: &str,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
                    .id(SessionId::new(session_id))
                    .user_id(UserId::new(user_id))
                    .user_agent(Some("test".to_string()))
                    .ip_address(Some("127.0.0.1".to_string()))
                    .created_at(now)
                    .updated_at(now)
                    .expires_at(now + expires_in)
                    .build()
                    .expect("Failed to build session"),
            )
            .await
    }

    #[tokio::test]
    async fn test_sqlite_storage() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test1@example.com"));

        let fetched = storage
            .get_user(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test1@example.com")
        );

        storage
            .delete_user(&UserId::new("1"))
            .await
            .expect("Failed to delete user");
        let deleted = storage
            .get_user(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_session_storage() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        let _session = create_test_session(&storage, "1", "1", Duration::from_secs(1000))
            .await
            .expect("Failed to create session");

        let fetched = storage
            .get_session(&SessionId::new("1"))
            .await
            .expect("Failed to get session")
            .expect("Session should exist");
        assert_eq!(fetched.user_id, UserId::new("1"));

        storage
            .delete_session(&SessionId::new("1"))
            .await
            .expect("Failed to delete session");
        let deleted = storage.get_session(&SessionId::new("1")).await;
        assert!(deleted.is_err());
    }

    #[tokio::test]
    async fn test_sqlite_session_cleanup() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Create an already expired session by setting expires_at in the past
        let expired_session = Session {
            id: SessionId::new("expired"),
            user_id: UserId::new("1"),
            user_agent: None,
            ip_address: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() - chrono::Duration::seconds(1),
        };
        storage
            .create_session(&expired_session)
            .await
            .expect("Failed to create expired session");

        // Create valid session
        create_test_session(&storage, "valid", "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create valid session");

        // Run cleanup
        storage
            .cleanup_expired_sessions()
            .await
            .expect("Failed to cleanup sessions");

        // Verify expired session was removed
        let expired_session = storage.get_session(&SessionId::new("expired")).await;
        assert!(expired_session.is_err());

        // Verify valid session remains
        let valid_session = storage
            .get_session(&SessionId::new("valid"))
            .await
            .expect("Failed to get valid session");
        assert!(valid_session.is_some());
    }

    #[tokio::test]
    async fn test_delete_sessions_for_user() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test users
        create_test_user(&storage, "1")
            .await
            .expect("Failed to create user 1");
        create_test_user(&storage, "2")
            .await
            .expect("Failed to create user 2");

        // Create sessions for user 1
        create_test_session(&storage, "session1", "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 1");
        create_test_session(&storage, "session2", "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 2");

        // Create session for user 2
        create_test_session(&storage, "session3", "2", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 3");

        // Delete all sessions for user 1
        storage
            .delete_sessions_for_user(&UserId::new("1"))
            .await
            .expect("Failed to delete sessions for user");

        // Verify user 1's sessions are deleted
        let session1 = storage.get_session(&SessionId::new("session1")).await;
        assert!(session1.is_err());
        let session2 = storage.get_session(&SessionId::new("session2")).await;
        assert!(session2.is_err());

        // Verify user 2's session remains
        let session3 = storage
            .get_session(&SessionId::new("session3"))
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
    }
}
