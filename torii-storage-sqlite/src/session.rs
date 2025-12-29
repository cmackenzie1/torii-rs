//! SQLite session test utilities

#[cfg(test)]
pub(crate) mod test {
    use crate::SqliteStorage;
    use crate::repositories::SqliteSessionRepository;
    use crate::tests::{create_test_user, setup_sqlite_storage};
    use chrono::Utc;
    use std::time::Duration;
    use torii_core::{Session, UserId, repositories::SessionRepository, session::SessionToken};

    pub(crate) async fn create_test_session(
        storage: &SqliteStorage,
        token: &SessionToken,
        user_id: &str,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let session_repo = SqliteSessionRepository::new(storage.pool.clone());
        let now = Utc::now();
        session_repo
            .create(
                Session::builder()
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
        let session_repo = SqliteSessionRepository::new(storage.pool.clone());
        create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        let token = SessionToken::new_random();
        let _session = create_test_session(&storage, &token, "1", Duration::from_secs(1000))
            .await
            .expect("Failed to create session");

        let fetched = session_repo
            .find_by_token(&token)
            .await
            .expect("Failed to get session");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().user_id, UserId::new("1"));

        session_repo
            .delete(&token)
            .await
            .expect("Failed to delete session");
        let deleted = session_repo
            .find_by_token(&token)
            .await
            .expect("Failed to get session");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_session_cleanup() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let session_repo = SqliteSessionRepository::new(storage.pool.clone());
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

        session_repo
            .create(expired_session)
            .await
            .expect("Failed to create expired session");

        // Create valid session
        let valid_token = SessionToken::new_random();
        create_test_session(&storage, &valid_token, "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create valid session");

        // Run cleanup
        session_repo
            .cleanup_expired()
            .await
            .expect("Failed to cleanup sessions");

        // Verify expired session was removed
        let expired_result = session_repo
            .find_by_token(&expired_token)
            .await
            .expect("Failed to get session");
        assert!(expired_result.is_none());

        // Verify valid session remains
        let valid_session = session_repo
            .find_by_token(&valid_token)
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
        let session_repo = SqliteSessionRepository::new(storage.pool.clone());

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
        session_repo
            .delete_by_user_id(&UserId::new("1"))
            .await
            .expect("Failed to delete sessions for user");

        // Verify user 1's sessions are deleted
        let session1 = session_repo
            .find_by_token(&token1)
            .await
            .expect("Failed to get session");
        assert!(session1.is_none());
        let session2 = session_repo
            .find_by_token(&token2)
            .await
            .expect("Failed to get session");
        assert!(session2.is_none());

        // Verify user 2's session remains
        let session3 = session_repo
            .find_by_token(&token3)
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
        assert_eq!(session3.unwrap().user_id, UserId::new("2"));
    }
}
