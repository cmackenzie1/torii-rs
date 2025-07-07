use crate::SqliteStorage;
use async_trait::async_trait;
use chrono::Utc;
use torii_core::UserId;
use torii_core::error::StorageError;
use torii_core::storage::PasskeyStorage;

#[async_trait]
impl PasskeyStorage for SqliteStorage {
    async fn add_passkey(
        &self,
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
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let passkey: Option<String> = sqlx::query_scalar(
            r#"
            SELECT public_key 
            FROM passkeys 
            WHERE credential_id = ?
            "#,
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(passkey)
    }

    async fn get_passkeys(&self, user_id: &UserId) -> Result<Vec<String>, torii_core::Error> {
        let passkeys: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT public_key 
            FROM passkeys 
            WHERE user_id = ?
            "#,
        )
        .bind(user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(passkeys)
    }

    async fn set_passkey_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
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
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(())
    }

    async fn get_passkey_challenge(
        &self,
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
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;
        Ok(challenge)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use sqlx::SqlitePool;
    use torii_core::{NewUser, User, UserStorage, storage::PasskeyStorage};

    use crate::SqliteStorage;

    async fn setup_sqlite_storage() -> SqliteStorage {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let storage = SqliteStorage::new(pool);
        storage.migrate().await.unwrap();
        storage
    }

    async fn create_test_user(storage: &SqliteStorage) -> User {
        let user = NewUser::builder()
            .email("test@test.com".to_string())
            .build()
            .unwrap();
        storage.create_user(&user).await.unwrap()
    }

    #[tokio::test]
    async fn test_add_and_get_passkey() {
        let storage = setup_sqlite_storage().await;

        // Create a user
        let user = create_test_user(&storage).await;

        let credential_id = "credential_id";
        let passkey_json = "passkey_json";
        storage
            .add_passkey(&user.id, credential_id, passkey_json)
            .await
            .unwrap();

        let passkeys = storage.get_passkeys(&user.id).await.unwrap();
        assert_eq!(passkeys.len(), 1);
        assert_eq!(passkeys[0], passkey_json);
    }

    #[tokio::test]
    async fn test_set_and_get_passkey_challenge() {
        let storage = setup_sqlite_storage().await;

        let challenge_id = "challenge_id";
        let challenge = "challenge";
        let expires_in = Duration::minutes(5);
        storage
            .set_passkey_challenge(challenge_id, challenge, expires_in)
            .await
            .unwrap();

        let stored_challenge = storage.get_passkey_challenge(challenge_id).await.unwrap();
        assert!(stored_challenge.is_some());
        assert_eq!(stored_challenge.unwrap(), challenge);
    }
}
