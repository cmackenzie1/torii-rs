use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use sqlx::PgPool;
use std::time::Duration;
use torii_core::session::SessionId;
use torii_core::storage::{EmailPasswordStorage, OAuthStorage};
use torii_core::user::OAuthAccount;
use torii_core::Error;
use torii_core::{
    storage::{NewUser, SessionStorage, UserStorage},
    Session, User, UserId,
};

#[derive(Debug)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
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
pub struct PostgresUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PostgresUser> for User {
    fn from(user: PostgresUser) -> Self {
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

impl From<User> for PostgresUser {
    fn from(user: User) -> Self {
        PostgresUser {
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
impl UserStorage for PostgresStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            INSERT INTO users (id, email) 
            VALUES ($1::uuid, $2) 
            RETURNING id::text, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_ref())
        .bind(&user.email)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            Self::Error::Storage("Failed to create user".to_string())
        })?;

        Ok(user.into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id::text, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id::text = $1
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
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id::text, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = $1
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
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            UPDATE users 
            SET email = $1, name = $2, email_verified_at = $3, updated_at = $4 
            WHERE id::text = $5
            RETURNING id::text, email, name, email_verified_at, created_at, updated_at
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

        Ok(user.into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id::text = $1")
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
pub struct PostgresSession {
    id: String,
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<PostgresSession> for Session {
    fn from(session: PostgresSession) -> Self {
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

impl From<Session> for PostgresSession {
    fn from(session: Session) -> Self {
        PostgresSession {
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
impl SessionStorage for PostgresStorage {
    type Error = torii_core::Error;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
        sqlx::query("INSERT INTO sessions (id, user_id, user_agent, ip_address, created_at, updated_at, expires_at) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)")
            .bind(session.id.as_ref())
            .bind(session.user_id.as_ref())
            .bind(&session.user_agent)
            .bind(&session.ip_address)
            .bind(session.created_at)
            .bind(session.updated_at)
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create session");
                Self::Error::Storage("Failed to create session".to_string())
            })?;

        Ok(self.get_session(&session.id).await?.unwrap())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> {
        let session = sqlx::query_as::<_, PostgresSession>(
            r#"
            SELECT id::text, user_id::text, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE id::text = $1
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
        sqlx::query("DELETE FROM sessions WHERE id::text = $1")
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
        sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
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
        sqlx::query("DELETE FROM sessions WHERE user_id::text = $1")
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

#[derive(Default)]
pub struct PostgresOAuthAccountBuilder {
    user_id: Option<UserId>,
    provider: Option<String>,
    subject: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl PostgresOAuthAccountBuilder {
    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn provider(mut self, provider: String) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
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

    pub fn build(self) -> Result<PostgresOAuthAccount, Error> {
        let now = Utc::now();
        Ok(PostgresOAuthAccount {
            user_id: self
                .user_id
                .ok_or(Error::ValidationError("User ID is required".to_string()))?
                .to_string(),
            provider: self
                .provider
                .ok_or(Error::ValidationError("Provider is required".to_string()))?,
            subject: self
                .subject
                .ok_or(Error::ValidationError("Subject is required".to_string()))?,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
        })
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresOAuthAccount {
    user_id: String,
    provider: String,
    subject: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl PostgresOAuthAccount {
    pub fn builder() -> PostgresOAuthAccountBuilder {
        PostgresOAuthAccountBuilder::default()
    }

    pub fn new(user_id: UserId, provider: impl Into<String>, subject: impl Into<String>) -> Self {
        PostgresOAuthAccountBuilder::default()
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

impl From<PostgresOAuthAccount> for OAuthAccount {
    fn from(oauth_account: PostgresOAuthAccount) -> Self {
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

impl From<OAuthAccount> for PostgresOAuthAccount {
    fn from(oauth_account: OAuthAccount) -> Self {
        PostgresOAuthAccount::builder()
            .user_id(oauth_account.user_id)
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(oauth_account.created_at)
            .updated_at(oauth_account.updated_at)
            .build()
            .expect("Default builder should never fail")
    }
}

#[async_trait]
impl OAuthStorage for PostgresStorage {
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Self::Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1::uuid, $2, $3, $4, $5)")
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

        let oauth_account = sqlx::query_as::<_, PostgresOAuthAccount>(
            r#"
            SELECT user_id::text, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE user_id::text = $1
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

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Self::Error> {
        sqlx::query(
            "INSERT INTO nonces (id, value, expires_at) VALUES ($1::text, $2, $3) RETURNING value",
        )
        .bind(csrf_state)
        .bind(pkce_verifier)
        .bind(Utc::now() + expires_in)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get nonce");
            Self::Error::Storage("Failed to get nonce".to_string())
        })?;

        Ok(())
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Self::Error> {
        let nonce = sqlx::query_scalar("SELECT value FROM nonces WHERE id::text = $1")
            .bind(csrf_state)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get nonce");
                Self::Error::Storage("Failed to get nonce".to_string())
            })?;

        Ok(nonce)
    }

    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Self::Error> {
        let oauth_account = sqlx::query_as::<_, PostgresOAuthAccount>(
            r#"
            SELECT user_id::text, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE provider = $1 AND subject = $2
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
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id::text, email, name, email_verified_at, created_at, updated_at
            FROM users
            WHERE provider = $1 AND subject = $2
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
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1::uuid, $2, $3, $4, $5)")
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
impl EmailPasswordStorage for PostgresStorage {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id::text= $2")
            .bind(hash)
            .bind(user_id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        let result = sqlx::query_scalar("SELECT password_hash FROM users WHERE id::text = $1")
            .bind(user_id.as_ref())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::types::chrono::Utc;
    use std::time::Duration;
    use torii_core::session::SessionId;

    async fn setup_test_db() -> PostgresStorage {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/postgres")
            .await
            .expect("Failed to connect to postgres");

        let storage = PostgresStorage::new(pool);
        storage.migrate().await.expect("Failed to run migrations");
        storage
    }

    async fn create_test_user(
        storage: &PostgresStorage,
        id: &UserId,
    ) -> Result<User, torii_core::Error> {
        storage
            .create_user(
                &NewUser::builder()
                    .id(id.clone())
                    .email(format!("test{}@example.com", id))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
    }

    async fn create_test_session(
        storage: &PostgresStorage,
        session_id: &SessionId,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
                    .id(session_id.clone())
                    .user_id(user_id.clone())
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
    async fn test_postgres_storage() {
        let storage = setup_test_db().await;
        let user_id = UserId::new_random();
        let user = create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test{}@example.com", user_id));

        let fetched = storage
            .get_user(&user_id)
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test{}@example.com", user_id)
        );

        storage
            .delete_user(&user_id)
            .await
            .expect("Failed to delete user");
        let deleted = storage
            .get_user(&user_id)
            .await
            .expect("Failed to get user");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_postgres_session_storage() {
        let storage = setup_test_db().await;
        let user_id = UserId::new_random();
        let session_id = SessionId::new_random();
        create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        let _session =
            create_test_session(&storage, &session_id, &user_id, Duration::from_secs(1000))
                .await
                .expect("Failed to create session");

        let fetched = storage
            .get_session(&session_id)
            .await
            .expect("Failed to get session")
            .expect("Session should exist");
        assert_eq!(fetched.user_id, user_id);

        storage
            .delete_session(&session_id)
            .await
            .expect("Failed to delete session");
        let deleted = storage.get_session(&session_id).await;
        assert!(deleted.is_err());
    }

    #[tokio::test]
    async fn test_postgres_session_cleanup() {
        let storage = setup_test_db().await;
        let user_id = UserId::new_random();
        create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        // Create an already expired session by setting expires_at in the past
        let session_id = SessionId::new_random();
        let expired_session = Session {
            id: SessionId::new_random(),
            user_id: user_id.clone(),
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
        create_test_session(&storage, &session_id, &user_id, Duration::from_secs(3600))
            .await
            .expect("Failed to create valid session");

        // Run cleanup
        storage
            .cleanup_expired_sessions()
            .await
            .expect("Failed to cleanup sessions");

        // Verify expired session was removed
        let expired_session = storage.get_session(&expired_session.id).await;
        assert!(expired_session.is_err());

        // Verify valid session remains
        let valid_session = storage
            .get_session(&session_id)
            .await
            .expect("Failed to get valid session")
            .expect("Session should exist");
        assert_eq!(valid_session.user_id, user_id);
    }

    #[tokio::test]
    async fn test_delete_sessions_for_user() {
        let storage = setup_test_db().await;

        // Create test users
        let user_id1 = UserId::new_random();
        create_test_user(&storage, &user_id1)
            .await
            .expect("Failed to create user 1");
        let user_id2 = UserId::new_random();
        create_test_user(&storage, &user_id2)
            .await
            .expect("Failed to create user 2");

        // Create sessions for user 1
        let session_id1 = SessionId::new_random();
        create_test_session(&storage, &session_id1, &user_id1, Duration::from_secs(3600))
            .await
            .expect("Failed to create session 1");
        let session_id2 = SessionId::new_random();
        create_test_session(&storage, &session_id2, &user_id1, Duration::from_secs(3600))
            .await
            .expect("Failed to create session 2");

        // Create session for user 2
        let session_id3 = SessionId::new_random();
        create_test_session(&storage, &session_id3, &user_id2, Duration::from_secs(3600))
            .await
            .expect("Failed to create session 3");

        // Delete all sessions for user 1
        storage
            .delete_sessions_for_user(&user_id1)
            .await
            .expect("Failed to delete sessions for user");

        // Verify user 1's sessions are deleted
        let session1 = storage.get_session(&session_id1).await;
        assert!(session1.is_err());
        let session2 = storage.get_session(&session_id2).await;
        assert!(session2.is_err());

        // Verify user 2's session remains
        let session3 = storage
            .get_session(&session_id3)
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
    }
}
