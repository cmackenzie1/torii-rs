use crate::SqliteStorage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::error::StorageError;
use torii_core::session::SessionToken;
use torii_core::{Session, SessionStorage, UserId};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteSession {
    #[allow(dead_code)]
    id: Option<i64>,
    token: String,
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
            .token(SessionToken::new(&session.token))
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
            id: None,
            token: session.token.into_inner(),
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
    async fn create_session(&self, session: &Session) -> Result<Session, torii_core::Error> {
        let session = sqlx::query_as::<_, SqliteSession>(
            r#"
            INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id, token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            "#,
        )
            .bind(session.token.as_str())
            .bind(session.user_id.as_str())
            .bind(&session.user_agent)
            .bind(&session.ip_address)
            .bind(session.created_at.timestamp())
            .bind(session.updated_at.timestamp())
            .bind(session.expires_at.timestamp())
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create session");
                StorageError::Database("Failed to create session".to_string())
            })?;

        Ok(session.into())
    }

    async fn get_session(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session>, torii_core::Error> {
        let session = sqlx::query_as::<_, SqliteSession>(
            r#"
            SELECT id, token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE token = ?
            "#,
        )
        .bind(token.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get session");
            StorageError::Database("Failed to get session".to_string())
        })?;

        Ok(Some(session.into()))
    }

    async fn delete_session(&self, token: &SessionToken) -> Result<(), torii_core::Error> {
        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(token.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete session");
                StorageError::Database("Failed to delete session".to_string())
            })?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), torii_core::Error> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(Utc::now().timestamp())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to cleanup expired sessions");
                StorageError::Database("Failed to cleanup expired sessions".to_string())
            })?;

        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), torii_core::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?")
            .bind(user_id.as_str())
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
pub(crate) mod test {
    use super::*;
    use crate::tests::{create_test_user, setup_sqlite_storage};
    use std::time::Duration;

    pub(crate) async fn create_test_session(
        storage: &SqliteStorage,
        session_id: &str,
        user_id: &str,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
                    .token(SessionToken::new(session_id))
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
            .get_session(&SessionToken::new("1"))
            .await
            .expect("Failed to get session");
        assert_eq!(fetched.unwrap().user_id, UserId::new("1"));

        storage
            .delete_session(&SessionToken::new("1"))
            .await
            .expect("Failed to delete session");
        let deleted = storage.get_session(&SessionToken::new("1")).await;
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
            token: SessionToken::new("expired"),
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
        let expired_session = storage.get_session(&SessionToken::new("expired")).await;
        assert!(expired_session.is_err());

        // Verify valid session remains
        let valid_session = storage
            .get_session(&SessionToken::new("valid"))
            .await
            .expect("Failed to get valid session");
        assert_eq!(valid_session.unwrap().user_id, UserId::new("1"));
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
        let session1 = storage.get_session(&SessionToken::new("session1")).await;
        assert!(session1.is_err());
        let session2 = storage.get_session(&SessionToken::new("session2")).await;
        assert!(session2.is_err());

        // Verify user 2's session remains
        let session3 = storage
            .get_session(&SessionToken::new("session3"))
            .await
            .expect("Failed to get session 3");
        assert_eq!(session3.unwrap().user_id, UserId::new("2"));
    }
}
