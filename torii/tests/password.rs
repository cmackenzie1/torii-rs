use std::sync::Arc;

use torii::{SessionConfig, Torii};
use torii_core::session::{JwtConfig, SessionToken};

#[cfg(feature = "sqlite")]
use torii::SqliteStorage;

// Test secret for HS256
const TEST_HS256_SECRET: &[u8] = b"this_is_a_test_secret_key_for_hs256_jwt_tokens_not_for_prod";

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_register_user_with_password() {
    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create Torii instance with password plugin
    let torii = Torii::new(sqlite.clone(), sqlite.clone()).with_password_plugin();

    // Register a user
    let email = "test@example.com";
    let password = "password123";
    let user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();

    // Verify user details
    assert_eq!(user.email, email);
    assert!(!user.is_email_verified());

    // Verify email
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Get user and verify email is verified
    let user = torii.get_user(&user.id).await.unwrap().unwrap();
    assert!(user.is_email_verified());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_login_with_password() {
    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create Torii instance with password plugin
    let torii = Torii::new(sqlite.clone(), sqlite.clone()).with_password_plugin();

    // Register a user and verify email
    let email = "test@example.com";
    let password = "password123";
    let user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login with correct credentials
    let user_agent = Some("Test User Agent".to_string());
    let ip_address = Some("127.0.0.1".to_string());
    let (logged_in_user, session) = torii
        .login_user_with_password(email, password, user_agent.clone(), ip_address.clone())
        .await
        .unwrap();

    // Verify user and session
    assert_eq!(logged_in_user.id, user.id);
    assert_eq!(logged_in_user.email, email);
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.user_agent, user_agent);
    assert_eq!(session.ip_address, ip_address);
    assert!(!session.is_expired());

    // Try login with incorrect password
    let result = torii
        .login_user_with_password(email, "wrong-password", None, None)
        .await;
    assert!(result.is_err());

    // Try login with non-existent user
    let result = torii
        .login_user_with_password("nonexistent@example.com", password, None, None)
        .await;
    assert!(result.is_err());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_login_with_unverified_email() {
    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create Torii instance with password plugin
    let torii = Torii::new(sqlite.clone(), sqlite.clone()).with_password_plugin();

    // Register a user without verifying email
    let email = "unverified@example.com";
    let password = "password123";
    let _user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();

    // Attempt to login with unverified email
    let result = torii
        .login_user_with_password(email, password, None, None)
        .await;

    // Should fail because email is not verified
    assert!(result.is_err());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_session_expiration() {
    use chrono::Duration;
    use std::time::Duration as StdDuration;
    use tokio::time::sleep;

    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create Torii instance with password plugin and short session expiration
    let torii = Torii::new(sqlite.clone(), sqlite.clone())
        .with_password_plugin()
        .with_session_config(SessionConfig {
            expires_in: Duration::seconds(1), // Short expiry for testing
            jwt_config: None,
        });

    // Register a user and verify email
    let email = "test@example.com";
    let password = "password123";
    let user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login to create a session
    let (_, session) = torii
        .login_user_with_password(email, password, None, None)
        .await
        .unwrap();

    // Verify we can get the session immediately
    let retrieved = torii.get_session(&session.token).await.unwrap();
    assert_eq!(retrieved.user_id, user.id);

    // Wait for expiration
    sleep(StdDuration::from_secs(2)).await;

    // Try to get the expired session
    let result = torii.get_session(&session.token).await;
    assert!(result.is_err());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_multiple_sessions() {
    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create Torii instance with password plugin
    let torii = Torii::new(sqlite.clone(), sqlite.clone()).with_password_plugin();

    // Register a user and verify email
    let email = "test@example.com";
    let password = "password123";
    let user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Create multiple sessions for the same user
    let (_, session1) = torii
        .login_user_with_password(
            email,
            password,
            Some("Device 1".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .await
        .unwrap();

    let (_, session2) = torii
        .login_user_with_password(
            email,
            password,
            Some("Device 2".to_string()),
            Some("127.0.0.2".to_string()),
        )
        .await
        .unwrap();

    // Verify both sessions are valid
    let retrieved1 = torii.get_session(&session1.token).await.unwrap();
    let retrieved2 = torii.get_session(&session2.token).await.unwrap();

    assert_eq!(retrieved1.user_id, user.id);
    assert_eq!(retrieved2.user_id, user.id);
    assert_eq!(retrieved1.user_agent, Some("Device 1".to_string()));
    assert_eq!(retrieved2.user_agent, Some("Device 2".to_string()));

    // Delete one session
    torii.delete_session(&session1.token).await.unwrap();

    // Verify first session is deleted and second is still valid
    let result = torii.get_session(&session1.token).await;
    assert!(result.is_err());

    let retrieved2 = torii.get_session(&session2.token).await.unwrap();
    assert_eq!(retrieved2.user_id, user.id);

    // Delete all sessions for user
    torii.delete_sessions_for_user(&user.id).await.unwrap();

    // Verify both sessions are now invalid
    let result1 = torii.get_session(&session1.token).await;
    let result2 = torii.get_session(&session2.token).await;
    assert!(result1.is_err());
    assert!(result2.is_err());
}

#[cfg(all(feature = "password", feature = "sqlite"))]
#[tokio::test]
async fn test_password_auth_with_jwt() {
    // Set up SQLite storage
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    sqlite.migrate().await.unwrap();

    // Create a JWT config with HS256
    let jwt_config = JwtConfig::new_hs256(TEST_HS256_SECRET.to_vec())
        .with_issuer("torii-test-hs256")
        .with_metadata(true);

    // Create Torii with JWT sessions
    let torii = Torii::new(sqlite.clone(), sqlite.clone())
        .with_jwt_sessions(jwt_config)
        .with_password_plugin();

    // Register a user and verify email
    let email = "test@example.com";
    let password = "password123";
    let user = torii
        .register_user_with_password(email, password)
        .await
        .unwrap();
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login with correct credentials
    let (logged_in_user, session) = torii
        .login_user_with_password(email, password, None, None)
        .await
        .unwrap();

    // Verify user
    assert_eq!(logged_in_user.id, user.id);
    assert_eq!(logged_in_user.email, email);

    // Verify the token is a JWT
    match &session.token {
        SessionToken::Jwt(_) => {
            // Expected
        }
        _ => panic!("Expected JWT token"),
    }

    // Verify the session can be retrieved
    let retrieved = torii.get_session(&session.token).await.unwrap();
    assert_eq!(retrieved.user_id, user.id);

    // Try login with incorrect password
    let result = torii
        .login_user_with_password(email, "wrong-password", None, None)
        .await;
    assert!(result.is_err());
}
