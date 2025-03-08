use std::sync::Arc;
use testcontainers_modules::testcontainers::{ImageExt, runners::AsyncRunner};
use torii::{SeaORMStorage, Torii};

/// Sets up Torii with password authentication and tests the basic authentication flow.
async fn test_password_auth_flow(storage: Arc<SeaORMStorage>) {
    // Set up Torii with the storage
    let torii = Torii::new(storage.clone(), storage.clone()).with_password_plugin();

    // Ensure database is migrated
    storage.migrate().await.expect("Failed to migrate storage");

    // Register a test user
    let user = torii
        .register_user_with_password("test@example.com", "password")
        .await
        .expect("Failed to register user");
    assert_eq!(user.email, "test@example.com");

    // Attempt to login without verifying email (should fail)
    let result = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await;
    assert!(result.is_err(), "Login should fail with unverified email");

    // Verify the email
    torii
        .set_user_email_verified(&user.id)
        .await
        .expect("Failed to verify email");

    // Login after email verification (should succeed)
    let (user, session) = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await
        .expect("Failed to login user");
    assert_eq!(user.email, "test@example.com");
    assert!(!session.is_expired());
}

#[tokio::test]
async fn test_seaorm_postgres_password_auth() {
    let container = testcontainers_modules::postgres::Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .expect("Failed to start Postgres container");

    let host_port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("Failed to get port");
    let connection_string = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");

    let storage = Arc::new(
        SeaORMStorage::connect(&connection_string)
            .await
            .expect("Failed to connect to database"),
    );

    test_password_auth_flow(storage).await;
}

#[tokio::test]
async fn test_seaorm_mysql_password_auth() {
    let _ = tracing_subscriber::fmt::try_init();

    let container = testcontainers_modules::mysql::Mysql::default()
        .with_tag("8")
        .start()
        .await
        .expect("Failed to start MySQL container");

    let host_port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("Failed to get port");
    let connection_string = format!("mysql://127.0.0.1:{host_port}/test");

    let storage = Arc::new(
        SeaORMStorage::connect(&connection_string)
            .await
            .expect("Failed to connect to database"),
    );

    test_password_auth_flow(storage).await;
}

#[tokio::test]
async fn test_seaorm_mariadb_password_auth() {
    let _ = tracing_subscriber::fmt::try_init();

    let container = testcontainers_modules::mariadb::Mariadb::default()
        .with_tag("11")
        .start()
        .await
        .expect("Failed to start MariaDB container");

    let host_port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("Failed to get port");
    let connection_string = format!("mysql://127.0.0.1:{host_port}/test");

    let storage = Arc::new(
        SeaORMStorage::connect(&connection_string)
            .await
            .expect("Failed to connect to database"),
    );

    test_password_auth_flow(storage).await;
}

#[tokio::test]
async fn test_seaorm_sqlite_password_auth() {
    let storage = Arc::new(
        SeaORMStorage::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to database"),
    );

    test_password_auth_flow(storage).await;
}
