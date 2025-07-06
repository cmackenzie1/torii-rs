use std::sync::Arc;

use torii::{SqliteRepositoryProvider, Torii};
use torii_core::repositories::RepositoryProvider;

// Magic link tests are disabled until MagicLinkService methods are exposed in Torii API
// TODO: Re-enable once magic link methods are added to Torii struct

#[cfg(all(feature = "magic-link", feature = "sqlite"))]
#[tokio::test]
#[ignore]
async fn test_magic_link_auth() {
    // Set up SQLite storage
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let repositories = SqliteRepositoryProvider::new(pool);
    repositories.migrate().await.unwrap();

    // Create Torii instance with repository provider
    let torii = Torii::new(Arc::new(repositories));

    // Generate a token for a test email
    let email = "test@example.com";
    let magic_token = torii.generate_magic_token(email).await.unwrap();

    // Verify the token contains expected data
    assert!(!magic_token.token.is_empty());
    assert!(magic_token.token.len() > 32); // Should be a reasonably long token
    assert!(!magic_token.used()); // Token should not be used yet
    assert!(magic_token.expires_at > chrono::Utc::now()); // Should expire in the future

    // Verify the magic token
    let (user, session) = torii
        .verify_magic_token(&magic_token.token, None, None)
        .await
        .unwrap();

    // Verify user details
    assert_eq!(user.email, email);

    // Verify session
    assert_eq!(session.user_id, user.id);
    assert!(!session.is_expired());

    // Trying to verify the same token again should fail (one-time use)
    let result = torii
        .verify_magic_token(&magic_token.token, None, None)
        .await;
    assert!(result.is_err());
}

#[cfg(all(feature = "magic-link", feature = "sqlite"))]
#[tokio::test]
#[ignore]
async fn test_magic_link_expired_token() {
    use chrono::Duration;
    use std::time::Duration as StdDuration;
    use tokio::time::sleep;

    // Set up SQLite storage
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let repositories = SqliteRepositoryProvider::new(pool);
    repositories.migrate().await.unwrap();

    // Create Torii instance with magic link plugin
    let torii = Torii::new(Arc::new(repositories)).with_session_config(torii::SessionConfig {
        expires_in: Duration::seconds(2), // Short expiry for testing
        provider_type: torii::SessionProviderType::Opaque,
    });

    // Generate a token
    let email = "expired@example.com";
    let magic_token = torii.generate_magic_token(email).await.unwrap();

    // Wait for the token to expire (hardcoded in plugin to 10 minutes,
    // but we can't wait that long in a test, so we'll mock this by directly checking
    // the error message when trying to verify)
    sleep(StdDuration::from_secs(2)).await;

    // We can't easily test token expiration in a unit test since the expiry is hardcoded
    // in the MagicLinkPlugin implementation. In a real application, you would make the
    // expiry time configurable.
    //
    // Instead, we'll verify that session expiration works by creating a session with
    // a short lifetime and checking that it expires.

    // Verify the token first
    let (_, session) = torii
        .verify_magic_token(&magic_token.token, None, None)
        .await
        .unwrap();

    // Wait for the session to expire
    sleep(StdDuration::from_secs(3)).await;

    // Get the session - should fail because it's expired
    let result = torii.get_session(&session.token).await;
    assert!(result.is_err());
}

#[cfg(all(feature = "magic-link", feature = "sqlite"))]
#[tokio::test]
#[ignore]
async fn test_magic_link_connection_info() {
    // Set up SQLite storage
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let repositories = SqliteRepositoryProvider::new(pool);
    repositories.migrate().await.unwrap();

    // Create Torii instance with repository provider
    let torii = Torii::new(Arc::new(repositories));

    // Generate a token
    let email = "connection@example.com";
    let magic_token = torii.generate_magic_token(email).await.unwrap();

    // Verify the token with connection info
    let user_agent = Some("Test User Agent".to_string());
    let ip_address = Some("127.0.0.1".to_string());

    let (_, session) = torii
        .verify_magic_token(&magic_token.token, user_agent.clone(), ip_address.clone())
        .await
        .unwrap();

    // Verify session has the connection info
    assert_eq!(session.user_agent, user_agent);
    assert_eq!(session.ip_address, ip_address);
}
