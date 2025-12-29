//! PostgreSQL passkey types and tests

#[cfg(test)]
mod tests {
    use crate::PostgresStorage;
    use crate::repositories::PostgresUserRepository;
    use crate::tests::setup_test_db;
    use chrono::Duration;
    use chrono::Utc;
    use torii_core::User;
    use torii_core::error::StorageError;
    use torii_core::repositories::UserRepository;
    use torii_core::storage::NewUser;

    async fn create_test_user(storage: &PostgresStorage) -> User {
        let user_repo = PostgresUserRepository::new(storage.pool.clone());
        let user = NewUser::builder()
            .email("test@test.com".to_string())
            .build()
            .unwrap();
        user_repo.create(user).await.unwrap()
    }

    async fn add_passkey(
        storage: &PostgresStorage,
        user_id: &torii_core::UserId,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            r#"
            INSERT INTO passkeys (credential_id, user_id, public_key) 
            VALUES ($1, $2, $3)
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
        storage: &PostgresStorage,
        user_id: &torii_core::UserId,
    ) -> Result<Vec<String>, torii_core::Error> {
        let passkeys: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT public_key 
            FROM passkeys 
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_str())
        .fetch_all(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(passkeys)
    }

    async fn set_passkey_challenge(
        storage: &PostgresStorage,
        challenge_id: &str,
        challenge: &str,
        expires_in: Duration,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            r#"
            INSERT INTO passkey_challenges (challenge_id, challenge, expires_at) 
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(challenge_id)
        .bind(challenge)
        .bind(Utc::now() + expires_in)
        .execute(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    async fn get_passkey_challenge(
        storage: &PostgresStorage,
        challenge_id: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let challenge: Option<String> = sqlx::query_scalar(
            r#"
            SELECT challenge 
            FROM passkey_challenges 
            WHERE challenge_id = $1 AND expires_at > $2
            "#,
        )
        .bind(challenge_id)
        .bind(Utc::now())
        .fetch_optional(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(challenge)
    }

    #[tokio::test]
    async fn test_add_and_get_passkey() {
        let storage = setup_test_db().await;

        // Create a user
        let user = create_test_user(&storage).await;

        let credential_id = uuid::Uuid::new_v4().to_string();
        let passkey_json = "passkey_json";
        add_passkey(&storage, &user.id, &credential_id, passkey_json)
            .await
            .unwrap();

        let passkeys = get_passkeys(&storage, &user.id).await.unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0], passkey_json);
    }

    #[tokio::test]
    async fn test_set_and_get_passkey_challenge() {
        let storage = setup_test_db().await;

        let challenge_id = uuid::Uuid::new_v4().to_string();
        let challenge = "challenge";
        let expires_in = Duration::minutes(5);
        set_passkey_challenge(&storage, &challenge_id, challenge, expires_in)
            .await
            .unwrap();

        let stored_challenge = get_passkey_challenge(&storage, &challenge_id)
            .await
            .unwrap();
        assert!(stored_challenge.is_some());
        assert_eq!(stored_challenge.unwrap(), challenge);
    }
}
