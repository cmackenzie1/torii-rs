//! SQLite passkey types and tests
//!
//! The actual passkey repository implementation is in the repositories module.

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use chrono::Utc;
    use sqlx::SqlitePool;
    use torii_core::error::StorageError;
    use torii_core::repositories::UserRepository;
    use torii_core::storage::NewUser;
    use torii_core::{User, UserId};

    use crate::SqliteStorage;
    use crate::repositories::SqliteUserRepository;

    async fn setup_sqlite_storage() -> SqliteStorage {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let storage = SqliteStorage::new(pool);
        storage.migrate().await.unwrap();
        storage
    }

    async fn create_test_user(storage: &SqliteStorage) -> User {
        let user_repo = SqliteUserRepository::new(storage.pool.clone());
        let user = NewUser::builder()
            .email("test@test.com".to_string())
            .build()
            .unwrap();
        user_repo.create(user).await.unwrap()
    }

    async fn add_passkey(
        storage: &SqliteStorage,
        user_id: &UserId,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            r#"
            INSERT INTO passkeys (credential_id, user_id, public_key) 
            VALUES (?, ?, ?)
            "#,
        )
        .bind(credential_id)
        .bind(user_id.as_str())
        .bind(passkey_json)
        .execute(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    async fn get_passkeys(
        storage: &SqliteStorage,
        user_id: &UserId,
    ) -> Result<Vec<String>, torii_core::Error> {
        let passkeys: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT public_key 
            FROM passkeys 
            WHERE user_id = ?
            "#,
        )
        .bind(user_id.as_str())
        .fetch_all(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(passkeys)
    }

    async fn set_passkey_challenge(
        storage: &SqliteStorage,
        challenge_id: &str,
        challenge: &str,
        expires_in: Duration,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            r#"
            INSERT INTO passkey_challenges (challenge_id, challenge, expires_at) 
            VALUES (?, ?, ?)
            "#,
        )
        .bind(challenge_id)
        .bind(challenge)
        .bind((Utc::now() + expires_in).timestamp())
        .execute(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    async fn get_passkey_challenge(
        storage: &SqliteStorage,
        challenge_id: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let challenge: Option<String> = sqlx::query_scalar(
            r#"
            SELECT challenge 
            FROM passkey_challenges 
            WHERE challenge_id = ? AND expires_at > ?
            "#,
        )
        .bind(challenge_id)
        .bind(Utc::now().timestamp())
        .fetch_optional(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(challenge)
    }

    #[tokio::test]
    async fn test_add_and_get_passkey() {
        let storage = setup_sqlite_storage().await;

        // Create a user
        let user = create_test_user(&storage).await;

        let credential_id = "credential_id";
        let passkey_json = "passkey_json";
        add_passkey(&storage, &user.id, credential_id, passkey_json)
            .await
            .unwrap();

        let passkeys = get_passkeys(&storage, &user.id).await.unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0], passkey_json);
    }

    #[tokio::test]
    async fn test_set_and_get_passkey_challenge() {
        let storage = setup_sqlite_storage().await;

        let challenge_id = "challenge_id";
        let challenge = "challenge";
        let expires_in = Duration::minutes(5);
        set_passkey_challenge(&storage, challenge_id, challenge, expires_in)
            .await
            .unwrap();

        let stored_challenge = get_passkey_challenge(&storage, challenge_id).await.unwrap();
        assert!(stored_challenge.is_some());
        assert_eq!(stored_challenge.unwrap(), challenge);
    }
}
