use std::sync::Arc;

use torii::{SqliteRepositoryProvider, Torii};
use torii_core::repositories::RepositoryProvider;

#[tokio::test]
async fn test_sqlite_password_auth() {
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let repositories = SqliteRepositoryProvider::new(pool);
    repositories.migrate().await.unwrap();
    let torii = Torii::new(Arc::new(repositories));

    let user = torii
        .register_user_with_password("test@example.com", "password")
        .await
        .unwrap();
    assert_eq!(user.email, "test@example.com");

    // Login the user without verifying the email, should now succeed
    let (user, session) = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await
        .unwrap();
    assert_eq!(user.email, "test@example.com");
    assert!(!session.is_expired());
    assert!(!user.is_email_verified());

    // Verify the email
    torii.set_user_email_verified(&user.id).await.unwrap();

    // Login the user again, should still succeed
    let (user2, session2) = torii
        .login_user_with_password("test@example.com", "password", None, None)
        .await
        .unwrap();
    assert_eq!(user2.email, "test@example.com");
    assert!(!session2.is_expired());
    assert!(user2.is_email_verified());
}
