use crate::PostgresStorage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::error::StorageError;
use torii_core::session::SessionId;
use torii_core::{Session, SessionStorage, UserId};

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
                StorageError::Database("Failed to create session".to_string())
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
            StorageError::Database("Failed to get session".to_string())
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
                StorageError::Database("Failed to delete session".to_string())
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
                StorageError::Database("Failed to cleanup expired sessions".to_string())
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
                StorageError::Database("Failed to delete sessions for user".to_string())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::time::Duration;
    use torii_core::session::SessionId;
    use torii_core::{Session, UserId, UserStorage};

    #[tokio::test]
    async fn test_postgres_storage() {
        let storage = crate::tests::setup_test_db().await;
        let user_id = UserId::new_random();
        let user = crate::tests::create_test_user(&storage, &user_id)
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
        let storage = crate::tests::setup_test_db().await;
        let user_id = UserId::new_random();
        let session_id = SessionId::new_random();
        crate::tests::create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        let _session = crate::tests::create_test_session(
            &storage,
            &session_id,
            &user_id,
            Duration::from_secs(1000),
        )
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
        let storage = crate::tests::setup_test_db().await;
        let user_id = UserId::new_random();
        crate::tests::create_test_user(&storage, &user_id)
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
        crate::tests::create_test_session(
            &storage,
            &session_id,
            &user_id,
            Duration::from_secs(3600),
        )
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
        let storage = crate::tests::setup_test_db().await;

        // Create test users
        let user_id1 = UserId::new_random();
        crate::tests::create_test_user(&storage, &user_id1)
            .await
            .expect("Failed to create user 1");
        let user_id2 = UserId::new_random();
        crate::tests::create_test_user(&storage, &user_id2)
            .await
            .expect("Failed to create user 2");

        // Create sessions for user 1
        let session_id1 = SessionId::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_id1,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 1");
        let session_id2 = SessionId::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_id2,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 2");

        // Create session for user 2
        let session_id3 = SessionId::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_id3,
            &user_id2,
            Duration::from_secs(3600),
        )
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
