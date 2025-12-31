//! Tests for the Torii builder pattern

use torii::ToriiBuilder;

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_with_sqlite() {
    // Test basic builder usage with SQLite
    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Health check should work
    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_with_sqlite_pool() {
    // Test builder with existing pool
    let pool = sqlx::SqlitePool::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite");

    let torii = ToriiBuilder::new()
        .with_sqlite_pool(pool)
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Health check should work
    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_manual_migration() {
    // Test builder without auto-migration (default)
    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .build()
        .await
        .expect("Failed to build Torii");

    // Run migration manually
    torii.migrate().await.expect("Migration failed");

    // Health check should work
    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_with_session_expiry() {
    use chrono::Duration;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .with_session_expiry(Duration::days(7))
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_with_jwt_sessions() {
    use torii::JwtConfig;

    // Create a JWT config with HS256
    let secret = b"this_is_a_test_secret_key_for_hs256_jwt_tokens_not_for_prod";
    let jwt_config = JwtConfig::new_hs256(secret.to_vec())
        .expect("Failed to create JWT config")
        .with_issuer("torii-builder-test");

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .with_jwt_sessions(jwt_config)
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_with_brute_force_config() {
    use chrono::Duration;
    use torii::BruteForceProtectionConfig;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .with_brute_force_protection(BruteForceProtectionConfig {
            max_failed_attempts: 3,
            lockout_period: Duration::minutes(30),
            ..Default::default()
        })
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    torii.health_check().await.expect("Health check failed");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn test_builder_disabled_brute_force() {
    use torii::BruteForceProtectionConfig;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .with_brute_force_protection(BruteForceProtectionConfig::disabled())
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    torii.health_check().await.expect("Health check failed");
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn test_builder_full_auth_flow() {
    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Register a user
    let user = torii
        .password()
        .register("test@example.com", "password123")
        .await
        .expect("Failed to register user");
    assert_eq!(user.email, "test@example.com");

    // Verify email
    torii
        .set_user_email_verified(&user.id)
        .await
        .expect("Failed to verify email");

    // Login
    let (logged_in_user, session) = torii
        .password()
        .authenticate("test@example.com", "password123", None, None)
        .await
        .expect("Failed to authenticate");

    assert_eq!(logged_in_user.id, user.id);
    assert!(!session.is_expired());

    // Verify session
    let retrieved = torii
        .get_session(&session.token)
        .await
        .expect("Failed to get session");
    assert_eq!(retrieved.user_id, user.id);

    // Logout
    torii
        .delete_session(&session.token)
        .await
        .expect("Failed to delete session");
}

#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
#[tokio::test]
async fn test_builder_with_seaorm() {
    let torii = ToriiBuilder::new()
        .with_seaorm("sqlite::memory:")
        .await
        .expect("Failed to connect to SeaORM")
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Health check should work
    torii.health_check().await.expect("Health check failed");
}

#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
#[tokio::test]
async fn test_builder_with_seaorm_connection() {
    use sea_orm::Database;

    let connection = Database::connect("sqlite::memory:")
        .await
        .expect("Failed to connect to SeaORM");

    let torii = ToriiBuilder::new()
        .with_seaorm_connection(connection)
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Health check should work
    torii.health_check().await.expect("Health check failed");
}

#[cfg(all(feature = "sqlite", feature = "password"))]
#[tokio::test]
async fn test_builder_repositories_accessor() {
    use std::sync::Arc;

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await
        .expect("Failed to connect to SQLite")
        .apply_migrations(true)
        .build()
        .await
        .expect("Failed to build Torii");

    // Access the underlying repositories
    let repos: &Arc<_> = torii.repositories();

    // The repositories should be accessible
    // We can't do much with them directly in this test, but we verify access works
    assert!(std::mem::size_of_val(repos) > 0);
}
