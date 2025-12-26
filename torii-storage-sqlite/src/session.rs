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
    token: String, // This stores the hash, not plaintext
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}

#[async_trait]
impl SessionStorage for SqliteStorage {
    async fn create_session(&self, session: &Session) -> Result<Session, torii_core::Error> {
        // Store the hash, not the plaintext token
        let _result = sqlx::query(
            r#"
            INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&session.token_hash) // Store hash, not plaintext
        .bind(session.user_id.as_str())
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .bind(session.created_at.timestamp())
        .bind(session.updated_at.timestamp())
        .bind(session.expires_at.timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create session");
            StorageError::Database("Failed to create session".to_string())
        })?;

        // Return the original session (caller already has plaintext token)
        Ok(session.clone())
    }

    async fn get_session(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session>, torii_core::Error> {
        // Compute hash for lookup
        let token_hash = token.token_hash();

        let session = sqlx::query_as::<_, SqliteSession>(
            r#"
            SELECT id, token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE token = ?
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get session");
            StorageError::Database("Failed to get session".to_string())
        })?;

        match session {
            Some(s) => {
                // Verify using constant-time comparison
                if token.verify_hash(&s.token) {
                    Ok(Some(Session {
                        token: token.clone(),
                        token_hash: s.token,
                        user_id: UserId::new(&s.user_id),
                        user_agent: s.user_agent,
                        ip_address: s.ip_address,
                        created_at: DateTime::from_timestamp(s.created_at, 0)
                            .expect("Invalid timestamp"),
                        updated_at: DateTime::from_timestamp(s.updated_at, 0)
                            .expect("Invalid timestamp"),
                        expires_at: DateTime::from_timestamp(s.expires_at, 0)
                            .expect("Invalid timestamp"),
                    }))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn delete_session(&self, token: &SessionToken) -> Result<(), torii_core::Error> {
        let token_hash = token.token_hash();

        sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(&token_hash)
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
        token: &SessionToken,
        user_id: &str,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
                    .token(token.clone())
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

        let token = SessionToken::new_random();
        let _session = create_test_session(&storage, &token, "1", Duration::from_secs(1000))
            .await
            .expect("Failed to create session");

        let fetched = storage
            .get_session(&token)
            .await
            .expect("Failed to get session");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().user_id, UserId::new("1"));

        storage
            .delete_session(&token)
            .await
            .expect("Failed to delete session");
        let deleted = storage
            .get_session(&token)
            .await
            .expect("Failed to get session");
        assert!(deleted.is_none());
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
        let expired_token = SessionToken::new_random();
        let expired_session = Session::builder()
            .token(expired_token.clone())
            .user_id(UserId::new("1"))
            .expires_at(chrono::Utc::now() - chrono::Duration::seconds(1))
            .build()
            .unwrap();

        storage
            .create_session(&expired_session)
            .await
            .expect("Failed to create expired session");

        // Create valid session
        let valid_token = SessionToken::new_random();
        create_test_session(&storage, &valid_token, "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create valid session");

        // Run cleanup
        storage
            .cleanup_expired_sessions()
            .await
            .expect("Failed to cleanup sessions");

        // Verify expired session was removed
        let expired_result = storage
            .get_session(&expired_token)
            .await
            .expect("Failed to get session");
        assert!(expired_result.is_none());

        // Verify valid session remains
        let valid_session = storage
            .get_session(&valid_token)
            .await
            .expect("Failed to get valid session");
        assert!(valid_session.is_some());
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
        let token1 = SessionToken::new_random();
        create_test_session(&storage, &token1, "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 1");
        let token2 = SessionToken::new_random();
        create_test_session(&storage, &token2, "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 2");

        // Create session for user 2
        let token3 = SessionToken::new_random();
        create_test_session(&storage, &token3, "2", Duration::from_secs(3600))
            .await
            .expect("Failed to create session 3");

        // Delete all sessions for user 1
        storage
            .delete_sessions_for_user(&UserId::new("1"))
            .await
            .expect("Failed to delete sessions for user");

        // Verify user 1's sessions are deleted
        let session1 = storage
            .get_session(&token1)
            .await
            .expect("Failed to get session");
        assert!(session1.is_none());
        let session2 = storage
            .get_session(&token2)
            .await
            .expect("Failed to get session");
        assert!(session2.is_none());

        // Verify user 2's session remains
        let session3 = storage
            .get_session(&token3)
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
        assert_eq!(session3.unwrap().user_id, UserId::new("2"));
    }
}
