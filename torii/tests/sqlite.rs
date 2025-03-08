use std::sync::Arc;

use torii::{SqliteStorage, Torii};

#[tokio::test]
async fn test_sqlite_password_auth() {
    let sqlite = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
    let torii = Torii::new(sqlite.clone(), sqlite.clone()).with_password_plugin();
    sqlite.migrate().await.unwrap(); // TODO(now): Move this to Torii::initialize()

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
