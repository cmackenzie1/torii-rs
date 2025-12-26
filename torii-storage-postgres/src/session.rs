use crate::PostgresStorage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::error::StorageError;
use torii_core::session::SessionToken;
use torii_core::{Session, SessionStorage, UserId};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresSession {
    #[allow(dead_code)]
    pub id: Option<i64>,
    pub user_id: String,
    pub token: String, // This stores the hash, not plaintext
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[async_trait]
impl SessionStorage for PostgresStorage {
    async fn create_session(&self, session: &Session) -> Result<Session, torii_core::Error> {
        // Store the hash, not the plaintext token
        sqlx::query("INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)")
            .bind(&session.token_hash) // Store hash, not plaintext
            .bind(session.user_id.as_str())
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

        // Return the original session (caller already has plaintext token)
        Ok(session.clone())
    }

    async fn get_session(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session>, torii_core::Error> {
        // Compute hash for lookup
        let token_hash = token.token_hash();

        let session = sqlx::query_as::<_, PostgresSession>(
            r#"
            SELECT id, token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE token = $1
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
                        created_at: s.created_at,
                        updated_at: s.updated_at,
                        expires_at: s.expires_at,
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

        sqlx::query("DELETE FROM sessions WHERE token = $1")
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

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), torii_core::Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
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
mod test {
    use super::*;
    use std::time::Duration;
    use torii_core::session::SessionToken;
    use torii_core::{Session, UserId, UserStorage};

    #[tokio::test]
    async fn test_postgres_storage() {
        let storage = crate::tests::setup_test_db().await;
        let user_id = UserId::new_random();
        let user = crate::tests::create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test{user_id}@example.com"));

        let fetched = storage
            .get_user(&user_id)
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test{user_id}@example.com")
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
        let session_token = SessionToken::new_random();
        crate::tests::create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        let _session = crate::tests::create_test_session(
            &storage,
            &session_token,
            &user_id,
            Duration::from_secs(1000),
        )
        .await
        .expect("Failed to create session");

        let fetched = storage
            .get_session(&session_token)
            .await
            .expect("Failed to get session");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().user_id, user_id);

        storage
            .delete_session(&session_token)
            .await
            .expect("Failed to delete session");
        let deleted = storage
            .get_session(&session_token)
            .await
            .expect("Failed to get session");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_postgres_session_cleanup() {
        let storage = crate::tests::setup_test_db().await;
        let user_id = UserId::new_random();
        crate::tests::create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        // Create an already expired session by setting expires_at in the past
        let session_token = SessionToken::new_random();
        let expired_session = Session::builder()
            .token(SessionToken::new_random())
            .user_id(user_id.clone())
            .expires_at(chrono::Utc::now() - chrono::Duration::seconds(1))
            .build()
            .unwrap();

        storage
            .create_session(&expired_session)
            .await
            .expect("Failed to create expired session");

        // Create valid session
        crate::tests::create_test_session(
            &storage,
            &session_token,
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
        let expired_result = storage
            .get_session(&expired_session.token)
            .await
            .expect("Failed to get session");
        assert!(expired_result.is_none());

        // Verify valid session remains
        let valid_session = storage
            .get_session(&session_token)
            .await
            .expect("Failed to get valid session");
        assert!(valid_session.is_some());
        assert_eq!(valid_session.unwrap().user_id, user_id);
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
        let session_token1 = SessionToken::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_token1,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 1");
        let session_token2 = SessionToken::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_token2,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 2");

        // Create session for user 2
        let session_token3 = SessionToken::new_random();
        crate::tests::create_test_session(
            &storage,
            &session_token3,
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
        let session1 = storage
            .get_session(&session_token1)
            .await
            .expect("Failed to get session");
        assert!(session1.is_none());
        let session2 = storage
            .get_session(&session_token2)
            .await
            .expect("Failed to get session");
        assert!(session2.is_none());

        // Verify user 2's session remains
        let session3 = storage
            .get_session(&session_token3)
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
        assert_eq!(session3.unwrap().user_id, user_id2);
    }
}
