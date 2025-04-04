use std::sync::Arc;

use chrono::Duration;
use torii::{SessionConfig, Torii};
use torii_core::session::{JwtConfig, SessionToken};
use torii_core::user::UserId;

#[cfg(feature = "sqlite")]
use torii::SqliteStorage;

// Test secret for HS256
const TEST_HS256_SECRET: &[u8] = b"this_is_a_test_secret_key_for_hs256_jwt_tokens_not_for_prod";

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_jwt_session_manager() {
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create a JWT config with HS256
    let jwt_config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec())
        .with_issuer("torii-test-hs256")
        .with_metadata(true);

    // Create a Torii instance with JWT sessions
    let torii = Torii::new(sqlite.clone()).with_jwt_sessions(jwt_config.clone());

    // Create a JWT session
    let user_id = UserId::new_random();
    let session = torii
        .create_session(
            &user_id,
            Some("test-agent-hs256".to_string()),
            Some("127.0.0.2".to_string()),
        )
        .await
        .unwrap();

    // Verify the token is a JWT
    match &session.token {
        SessionToken::Jwt(_) => {
            // Expected
        }
        _ => panic!("Expected JWT token"),
    }

    // Retrieve the session
    let retrieved = torii.get_session(&session.token).await.unwrap();
    assert_eq!(retrieved.user_id, user_id);
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_jwt_expiration() {
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create a JWT config with HS256
    let jwt_config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec());

    // Create Torii with a JWT session manager and short expiration
    let torii = Torii::new(sqlite.clone())
        .with_jwt_sessions(jwt_config.clone())
        .with_session_config(SessionConfig {
            expires_in: Duration::seconds(1),
            jwt_config: Some(jwt_config.clone()),
        });

    // Create a JWT session with a very short expiration
    let user_id = UserId::new_random();
    let session = torii.create_session(&user_id, None, None).await.unwrap();

    // Verify we can get the session immediately
    let retrieved = torii.get_session(&session.token).await.unwrap();
    assert_eq!(retrieved.user_id, user_id);

    // Wait for expiration
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Try to get the expired session
    let result = torii.get_session(&session.token).await;
    assert!(result.is_err());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_password_auth_with_jwt() {
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create a JWT config with HS256
    let jwt_config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec())
        .with_issuer("torii-test-hs256")
        .with_metadata(true);

    // Create Torii with JWT sessions
    let torii = Torii::new(sqlite.clone())
        .with_jwt_sessions(jwt_config)
        .with_password_plugin();

    // Register a user
    let user = torii
        .register_user_with_password("test@example.com", "password123")
        .await
        .unwrap();

    // Verify email (required for login)
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login with password
    let (user, session) = torii
        .login_user_with_password("test@example.com", "password123", None, None)
        .await
        .unwrap();

    // Verify the token is a JWT
    match &session.token {
        SessionToken::Jwt(_) => {
            // Expected
        }
        _ => panic!("Expected JWT token"),
    }

    // Verify the session contains the user ID
    assert_eq!(session.user_id, user.id);

    // Validate the session
    let retrieved = torii.get_session(&session.token).await.unwrap();
    assert_eq!(retrieved.user_id, user.id);

    // Try with incorrect password
    let result = torii
        .login_user_with_password("test@example.com", "wrong-password", None, None)
        .await;
    assert!(result.is_err());
}
