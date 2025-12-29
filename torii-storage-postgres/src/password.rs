//! PostgreSQL password storage tests

#[cfg(test)]
mod tests {
    use crate::repositories::PostgresPasswordRepository;
    use crate::tests::setup_test_db;
    use torii_core::UserId;
    use torii_core::repositories::PasswordRepository;
    use torii_core::storage::NewUser;

    async fn create_test_user(storage: &crate::PostgresStorage, user_id: &UserId) {
        use crate::repositories::PostgresUserRepository;
        use torii_core::repositories::UserRepository;

        let user_repo = PostgresUserRepository::new(storage.pool.clone());
        user_repo
            .create(
                NewUser::builder()
                    .id(user_id.clone())
                    .email(format!("test{}@example.com", user_id.as_str()))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
            .expect("Failed to create user");
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_set_and_get_password_hash() {
        let storage = setup_test_db().await;
        let password_repo = PostgresPasswordRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();
        let password_hash = "hashed_password_123";

        // First insert a test user
        create_test_user(&storage, &user_id).await;

        // Test setting password hash
        let result = password_repo
            .set_password_hash(&user_id, password_hash)
            .await;
        assert!(result.is_ok());

        // Test getting password hash
        let result = password_repo.get_password_hash(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(password_hash.to_string()));
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_get_password_hash_not_found() {
        let storage = setup_test_db().await;
        let password_repo = PostgresPasswordRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();

        let result = password_repo.get_password_hash(&user_id).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    #[ignore = "requires database"]
    async fn test_set_password_hash_nonexistent_user() {
        let storage = setup_test_db().await;
        let password_repo = PostgresPasswordRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();
        let password_hash = "hashed_password_123";

        let result = password_repo
            .set_password_hash(&user_id, password_hash)
            .await;
        // Should succeed but not actually update anything
        assert!(result.is_ok());
    }
}
