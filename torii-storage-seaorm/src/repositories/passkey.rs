use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use torii_core::{
    Error, UserId,
    repositories::{PasskeyCredential, PasskeyRepository},
};

use crate::SeaORMStorageError;
use crate::entities::{passkey, passkey_challenge};

pub struct SeaORMPasskeyRepository {
    pool: DatabaseConnection,
}

impl SeaORMPasskeyRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasskeyRepository for SeaORMPasskeyRepository {
    async fn add_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        use base64::prelude::*;

        let credential_id_b64 = BASE64_STANDARD.encode(&credential_id);

        // Create JSON representation of the credential
        let credential_json = serde_json::json!({
            "credential_id": credential_id_b64,
            "public_key": BASE64_STANDARD.encode(&public_key),
            "name": name,
            "created_at": Utc::now(),
            "last_used_at": Option::<DateTime<Utc>>::None
        });

        let passkey_model = passkey::ActiveModel {
            user_id: Set(user_id.to_string()),
            credential_id: Set(credential_id_b64),
            data_json: Set(credential_json.to_string()),
            ..Default::default()
        };

        passkey_model
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(PasskeyCredential {
            user_id: user_id.clone(),
            credential_id,
            public_key,
            name,
            created_at: Utc::now(),
            last_used_at: None,
        })
    }

    async fn get_credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        use base64::prelude::*;

        let passkeys = passkey::Entity::find()
            .filter(passkey::Column::UserId.eq(user_id.to_string()))
            .all(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        let mut credentials = Vec::new();
        for p in passkeys {
            let json: serde_json::Value = serde_json::from_str(&p.data_json).map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

            let credential_id = BASE64_STANDARD
                .decode(json["credential_id"].as_str().unwrap_or(""))
                .map_err(|e| {
                    Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                })?;

            let public_key = BASE64_STANDARD
                .decode(json["public_key"].as_str().unwrap_or(""))
                .map_err(|e| {
                    Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                })?;

            credentials.push(PasskeyCredential {
                user_id: user_id.clone(),
                credential_id,
                public_key,
                name: json["name"].as_str().map(|s| s.to_string()),
                created_at: serde_json::from_value(json["created_at"].clone())
                    .unwrap_or_else(|_| Utc::now()),
                last_used_at: serde_json::from_value(json["last_used_at"].clone()).unwrap_or(None),
            });
        }

        Ok(credentials)
    }

    async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        use base64::prelude::*;

        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);

        let passkey = passkey::Entity::find()
            .filter(passkey::Column::CredentialId.eq(&credential_id_b64))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(p) = passkey {
            let json: serde_json::Value = serde_json::from_str(&p.data_json).map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

            let public_key = BASE64_STANDARD
                .decode(json["public_key"].as_str().unwrap_or(""))
                .map_err(|e| {
                    Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                })?;

            let user_id = UserId::new(&p.user_id);

            Ok(Some(PasskeyCredential {
                user_id,
                credential_id: credential_id.to_vec(),
                public_key,
                name: json["name"].as_str().map(|s| s.to_string()),
                created_at: serde_json::from_value(json["created_at"].clone())
                    .unwrap_or_else(|_| Utc::now()),
                last_used_at: serde_json::from_value(json["last_used_at"].clone()).unwrap_or(None),
            }))
        } else {
            Ok(None)
        }
    }

    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error> {
        use base64::prelude::*;

        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);

        let passkey = passkey::Entity::find()
            .filter(passkey::Column::CredentialId.eq(&credential_id_b64))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(p) = passkey {
            let mut json: serde_json::Value = serde_json::from_str(&p.data_json).map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

            json["last_used_at"] = serde_json::json!(Utc::now());

            let mut active: passkey::ActiveModel = p.into();
            active.data_json = Set(json.to_string());
            active
                .update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
        }

        Ok(())
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
        use base64::prelude::*;

        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);

        passkey::Entity::delete_many()
            .filter(passkey::Column::CredentialId.eq(&credential_id_b64))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        passkey::Entity::delete_many()
            .filter(passkey::Column::UserId.eq(user_id.to_string()))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }
}

// Internal helper methods for challenge storage
impl SeaORMPasskeyRepository {
    pub async fn set_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        let challenge_model = passkey_challenge::ActiveModel {
            challenge_id: Set(challenge_id.to_string()),
            challenge: Set(challenge.to_string()),
            expires_at: Set(Utc::now() + expires_in),
            ..Default::default()
        };

        challenge_model
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Option<String>, Error> {
        let challenge = passkey_challenge::Entity::find()
            .filter(passkey_challenge::Column::ChallengeId.eq(challenge_id))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(challenge.map(|c| c.challenge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::repositories::SeaORMUserRepository;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    async fn create_test_user(pool: &DatabaseConnection) -> UserId {
        let repo = SeaORMUserRepository::new(pool.clone());
        let user = repo
            .create_user("test@example.com", Some("Test User"))
            .await
            .unwrap();
        user.id
    }

    #[tokio::test]
    async fn test_add_and_get_credential() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasskeyRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let credential_id = vec![1, 2, 3, 4, 5];
        let public_key = vec![6, 7, 8, 9, 10];
        let name = Some("Test Passkey".to_string());

        let credential = repo
            .add_credential(
                &user_id,
                credential_id.clone(),
                public_key.clone(),
                name.clone(),
            )
            .await
            .unwrap();

        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.name, name);

        // Get credentials for user
        let credentials = repo.get_credentials_for_user(&user_id).await.unwrap();
        assert_eq!(credentials.len(), 1);
        assert_eq!(credentials[0].credential_id, credential_id);
    }

    #[tokio::test]
    async fn test_get_credential_by_id() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasskeyRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let credential_id = vec![1, 2, 3, 4, 5];
        let public_key = vec![6, 7, 8, 9, 10];

        repo.add_credential(&user_id, credential_id.clone(), public_key.clone(), None)
            .await
            .unwrap();

        let credential = repo.get_credential(&credential_id).await.unwrap();
        assert!(credential.is_some());
        assert_eq!(credential.unwrap().credential_id, credential_id);
    }

    #[tokio::test]
    async fn test_delete_credential() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasskeyRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let credential_id = vec![1, 2, 3, 4, 5];
        let public_key = vec![6, 7, 8, 9, 10];

        repo.add_credential(&user_id, credential_id.clone(), public_key, None)
            .await
            .unwrap();

        // Verify it exists
        let credential = repo.get_credential(&credential_id).await.unwrap();
        assert!(credential.is_some());

        // Delete it
        repo.delete_credential(&credential_id).await.unwrap();

        // Verify it's gone
        let credential = repo.get_credential(&credential_id).await.unwrap();
        assert!(credential.is_none());
    }

    #[tokio::test]
    async fn test_delete_all_for_user() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasskeyRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        // Add multiple credentials
        repo.add_credential(&user_id, vec![1, 2, 3], vec![4, 5, 6], None)
            .await
            .unwrap();
        repo.add_credential(&user_id, vec![7, 8, 9], vec![10, 11, 12], None)
            .await
            .unwrap();

        let credentials = repo.get_credentials_for_user(&user_id).await.unwrap();
        assert_eq!(credentials.len(), 2);

        // Delete all
        repo.delete_all_for_user(&user_id).await.unwrap();

        let credentials = repo.get_credentials_for_user(&user_id).await.unwrap();
        assert_eq!(credentials.len(), 0);
    }
}
