//! SQLite password storage tests

#[cfg(test)]
mod tests {
    use crate::repositories::SqlitePasswordRepository;
    use crate::tests::{create_test_user, setup_sqlite_storage};
    use torii_core::UserId;
    use torii_core::repositories::PasswordRepository;

    #[tokio::test]
    async fn test_password_hash() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let password_repo = SqlitePasswordRepository::new(storage.pool.clone());

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Set password hash
        let hash = "test_hash_123";
        password_repo
            .set_password_hash(&user.id, hash)
            .await
            .expect("Failed to set password hash");

        // Get password hash
        let stored_hash = password_repo
            .get_password_hash(&user.id)
            .await
            .expect("Failed to get password hash");

        assert_eq!(stored_hash, Some(hash.to_string()));

        // Get password hash for non-existent user
        let non_existent = password_repo
            .get_password_hash(&UserId::new("non_existent"))
            .await
            .expect("Failed to get password hash");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_password_hash_update() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let password_repo = SqlitePasswordRepository::new(storage.pool.clone());

        // Create test user with initial password hash
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        let initial_hash = "initial_hash_123";
        password_repo
            .set_password_hash(&user.id, initial_hash)
            .await
            .expect("Failed to set initial password hash");

        // Set updated password hash
        let updated_hash = "updated_hash_456";
        password_repo
            .set_password_hash(&user.id, updated_hash)
            .await
            .expect("Failed to set updated password hash");

        // Get updated password hash
        let stored_hash = password_repo
            .get_password_hash(&user.id)
            .await
            .expect("Failed to get updated password hash");

        assert_eq!(stored_hash, Some(updated_hash.to_string()));
    }
}
