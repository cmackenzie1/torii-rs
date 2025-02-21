use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use sqlx::SqlitePool;
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
    email_verified_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl From<SqliteUser> for User {
    fn from(user: SqliteUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at.map(|timestamp| {
                DateTime::from_timestamp(timestamp, 0).expect("Invalid timestamp")
            }))
            .created_at(DateTime::from_timestamp(user.created_at, 0).expect("Invalid timestamp"))
            .updated_at(DateTime::from_timestamp(user.updated_at, 0).expect("Invalid timestamp"))
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
            email_verified_at: user
                .email_verified_at
                .map(|timestamp| timestamp.timestamp()),
            created_at: user.created_at.timestamp(),
            updated_at: user.updated_at.timestamp(),
        }
    }
}

#[async_trait]
impl UserStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        let now = Utc::now();
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            INSERT INTO users (id, email, name, email_verified_at, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_ref())
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.email_verified_at)
        .bind(now.timestamp())
        .bind(now.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            Self::Error::Storage("Failed to create user".to_string())
        })?;

        Ok(user.into())
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
        let now = Utc::now();
        let user = sqlx::query_as::<_, SqliteUser>(
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
        .bind(now.timestamp())
        .bind(user.id.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            Self::Error::Storage("Failed to update user".to_string())
        })?;

        Ok(user.into())
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
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}

impl From<SqliteSession> for Session {
    fn from(session: SqliteSession) -> Self {
        Session::builder()
            .id(SessionId::new(&session.id))
            .user_id(UserId::new(&session.user_id))
            .user_agent(session.user_agent)
            .ip_address(session.ip_address)
            .created_at(DateTime::from_timestamp(session.created_at, 0).expect("Invalid timestamp"))
            .updated_at(DateTime::from_timestamp(session.updated_at, 0).expect("Invalid timestamp"))
            .expires_at(DateTime::from_timestamp(session.expires_at, 0).expect("Invalid timestamp"))
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
            created_at: session.created_at.timestamp(),
            updated_at: session.updated_at.timestamp(),
            expires_at: session.expires_at.timestamp(),
        }
    }
}

#[async_trait]
impl SessionStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
        let session = sqlx::query_as::<_, SqliteSession>(
            r#"
            INSERT INTO sessions (id, user_id, user_agent, ip_address, created_at, updated_at, expires_at) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            "#,
        )
            .bind(session.id.as_ref())
            .bind(session.user_id.as_ref())
            .bind(&session.user_agent)
            .bind(&session.ip_address)
            .bind(session.created_at.timestamp())
            .bind(session.updated_at.timestamp())
            .bind(session.expires_at.timestamp())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create session");
                Self::Error::Storage("Failed to create session".to_string())
            })?;

        Ok(session.into())
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
            .bind(Utc::now().timestamp())
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
    created_at: i64,
    updated_at: i64,
}

impl From<SqliteOAuthAccount> for OAuthAccount {
    fn from(oauth_account: SqliteOAuthAccount) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&oauth_account.user_id))
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(
                DateTime::from_timestamp(oauth_account.created_at, 0).expect("Invalid timestamp"),
            )
            .updated_at(
                DateTime::from_timestamp(oauth_account.updated_at, 0).expect("Invalid timestamp"),
            )
            .build()
            .unwrap()
    }
}

impl From<OAuthAccount> for SqliteOAuthAccount {
    fn from(oauth_account: OAuthAccount) -> Self {
        SqliteOAuthAccount {
            user_id: oauth_account.user_id.into_inner(),
            provider: oauth_account.provider,
            subject: oauth_account.subject,
            created_at: oauth_account.created_at.timestamp(),
            updated_at: oauth_account.updated_at.timestamp(),
        }
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
        let now = Utc::now();
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?)
            RETURNING user_id, provider, subject, created_at, updated_at
            "#,
        )
        .bind(user_id.as_ref())
        .bind(provider)
        .bind(subject)
        .bind(now.timestamp())
        .bind(now.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create oauth account");
            Self::Error::Storage("Failed to create oauth account".to_string())
        })?;

        Ok(oauth_account.into())
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Self::Error> {
        let pkce_verifier: Option<String> =
            sqlx::query_scalar("SELECT value FROM nonces WHERE id = ?")
                .bind(csrf_state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get pkce verifier");
                    Self::Error::Storage("Failed to get pkce verifier".to_string())
                })?;

        Ok(pkce_verifier)
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Self::Error> {
        sqlx::query("INSERT INTO nonces (id, value, expires_at) VALUES (?, ?, ?)")
            .bind(csrf_state)
            .bind(pkce_verifier)
            .bind(Utc::now() + expires_in)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to save pkce verifier");
                Self::Error::Storage("Failed to save pkce verifier".to_string())
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
        let now = Utc::now();
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user_id.as_ref())
            .bind(provider)
            .bind(subject)
            .bind(now.timestamp())
            .bind(now.timestamp())
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

    #[tokio::test]
    async fn test_timestamps_are_set_correctly() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Verify user timestamps are set
        assert!(user.created_at <= Utc::now());
        assert!(user.updated_at <= Utc::now());
        assert_eq!(user.created_at, user.updated_at);

        // Create test session
        let session = create_test_session(&storage, "session1", "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session");

        // Verify session timestamps are set
        assert!(session.created_at <= Utc::now());
        assert!(session.updated_at <= Utc::now());
        assert_eq!(session.created_at, session.updated_at);
        assert!(session.expires_at > Utc::now());

        // Update user

        tokio::time::sleep(Duration::from_secs(1)).await; // Need to sleep for at least 1 second to ensure the updated_at is different

        let mut updated_user = user.clone();
        updated_user.name = Some("Test User".to_string());
        let updated_user = storage
            .update_user(&updated_user)
            .await
            .expect("Failed to update user");

        // Verify updated timestamps
        assert_eq!(updated_user.created_at, user.created_at);
        assert!(updated_user.updated_at > user.updated_at);
    }
}
