//! PostgreSQL session test utilities

#[cfg(test)]
mod test {
    use crate::repositories::PostgresSessionRepository;
    use crate::tests::{create_test_session, create_test_user, setup_test_db};
    use std::time::Duration;
    use torii_core::repositories::SessionRepository;
    use torii_core::session::SessionToken;
    use torii_core::{Session, UserId};

    #[tokio::test]
    async fn test_postgres_storage() {
        let storage = setup_test_db().await;
        let user_id = UserId::new_random();
        let user = create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test{user_id}@example.com"));

        let user_repo = crate::repositories::PostgresUserRepository::new(storage.pool.clone());
        use torii_core::repositories::UserRepository;

        let fetched = user_repo
            .find_by_id(&user_id)
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test{user_id}@example.com")
        );

        user_repo
            .delete(&user_id)
            .await
            .expect("Failed to delete user");
        let deleted = user_repo
            .find_by_id(&user_id)
            .await
            .expect("Failed to get user");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_postgres_session_storage() {
        let storage = setup_test_db().await;
        let session_repo = PostgresSessionRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();
        let session_token = SessionToken::new_random();
        create_test_user(&storage, &user_id)
            .await
            .expect("Failed to create user");

        let _session = create_test_session(
            &storage,
            &session_token,
            &user_id,
            Duration::from_secs(1000),
        )
        .await
        .expect("Failed to create session");

        let fetched = session_repo
            .find_by_token(&session_token)
            .await
            .expect("Failed to get session");
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().user_id, user_id);

        session_repo
            .delete(&session_token)
            .await
            .expect("Failed to delete session");
        let deleted = session_repo
            .find_by_token(&session_token)
            .await
            .expect("Failed to get session");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_postgres_session_cleanup() {
        let storage = setup_test_db().await;
        let session_repo = PostgresSessionRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();
        create_test_user(&storage, &user_id)
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

        session_repo
            .create(expired_session.clone())
            .await
            .expect("Failed to create expired session");

        // Create valid session
        create_test_session(
            &storage,
            &session_token,
            &user_id,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create valid session");

        // Run cleanup
        session_repo
            .cleanup_expired()
            .await
            .expect("Failed to cleanup sessions");

        // Verify expired session was removed
        let expired_result = session_repo
            .find_by_token(
                expired_session
                    .token
                    .as_ref()
                    .expect("token should be present"),
            )
            .await
            .expect("Failed to get session");
        assert!(expired_result.is_none());

        // Verify valid session remains
        let valid_session = session_repo
            .find_by_token(&session_token)
            .await
            .expect("Failed to get valid session");
        assert!(valid_session.is_some());
        assert_eq!(valid_session.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn test_delete_sessions_for_user() {
        let storage = setup_test_db().await;
        let session_repo = PostgresSessionRepository::new(storage.pool.clone());

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
        let session_token1 = SessionToken::new_random();
        create_test_session(
            &storage,
            &session_token1,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 1");
        let session_token2 = SessionToken::new_random();
        create_test_session(
            &storage,
            &session_token2,
            &user_id1,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 2");

        // Create session for user 2
        let session_token3 = SessionToken::new_random();
        create_test_session(
            &storage,
            &session_token3,
            &user_id2,
            Duration::from_secs(3600),
        )
        .await
        .expect("Failed to create session 3");

        // Delete all sessions for user 1
        session_repo
            .delete_by_user_id(&user_id1)
            .await
            .expect("Failed to delete sessions for user");

        // Verify user 1's sessions are deleted
        let session1 = session_repo
            .find_by_token(&session_token1)
            .await
            .expect("Failed to get session");
        assert!(session1.is_none());
        let session2 = session_repo
            .find_by_token(&session_token2)
            .await
            .expect("Failed to get session");
        assert!(session2.is_none());

        // Verify user 2's session remains
        let session3 = session_repo
            .find_by_token(&session_token3)
            .await
            .expect("Failed to get session 3");
        assert!(session3.is_some());
        assert_eq!(session3.unwrap().user_id, user_id2);
    }
}
