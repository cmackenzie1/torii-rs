use std::sync::Arc;
use torii::Torii;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_basic_torii_functionality() -> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    // Create in-memory SQLite database
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));

    // Create Torii instance
    let torii = Torii::new(repositories);

    // Run migrations
    torii.migrate().await?;

    // Health check
    torii.health_check().await?;

    // Test basic user operations
    let user_id = torii_core::user::UserId::new("test-user");

    // Initially, user should not exist
    let user = torii.get_user(&user_id).await?;
    assert!(user.is_none());

    Ok(())
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn test_password_authentication() -> Result<(), Box<dyn std::error::Error>> {
    use torii::sqlite::SqliteRepositoryProvider;

    // Create in-memory SQLite database
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));

    // Create Torii instance
    let torii = Torii::new(repositories);

    // Run migrations
    torii.migrate().await?;

    // Register a user
    let user = torii
        .password()
        .register("test@example.com", "password123")
        .await?;
    assert_eq!(user.email, "test@example.com");
    assert!(!user.is_email_verified());

    // Verify the email
    torii.set_user_email_verified(&user.id).await?;

    // Login with correct password
    let (logged_in_user, session) = torii
        .password()
        .authenticate(
            "test@example.com",
            "password123",
            Some("test-agent".to_string()),
            Some("127.0.0.1".to_string()),
        )
        .await?;

    assert_eq!(logged_in_user.id, user.id);
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.user_agent, Some("test-agent".to_string()));

    // Try to login with wrong password
    let result = torii
        .password()
        .authenticate("test@example.com", "wrongpassword", None, None)
        .await;
    assert!(result.is_err());

    Ok(())
}
