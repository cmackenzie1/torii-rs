//! Postgres tests are currently disabled as PostgresRepositoryProvider is not yet implemented
//! TODO: Implement PostgresRepositoryProvider and re-enable these tests

#![allow(dead_code, unused_imports)]

use std::sync::Arc;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use torii::{PostgresStorage, Torii};

#[tokio::test]
async fn test_postgres_password_auth() {
    let container = testcontainers_modules::postgres::Postgres::default()
        .start()
        .await
        .unwrap();
    let host_port = container.get_host_port_ipv4(5432).await.unwrap();
    let connection_string =
        &format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres",);

    let pool = sqlx::PgPool::connect(connection_string).await.unwrap();
    let repositories = PostgresRepositoryProvider::new(pool);
    repositories.migrate().await.unwrap();
    let torii = Torii::new(Arc::new(repositories));

    let user = torii
        .register_user_with_password("test@example.com", "password")
        .await
        .unwrap();
    assert_eq!(user.email, "test@example.com");

    // Login the user without verifying the email, should fail
    let result = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await;
    assert!(result.is_err());

    // Verify the email
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login the user again, should succeed
    let (user, session) = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await
        .unwrap();
    assert_eq!(user.email, "test@example.com");
    assert!(!session.is_expired());
}
