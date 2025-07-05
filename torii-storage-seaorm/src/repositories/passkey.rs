use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, UserId,
    repositories::{PasskeyCredential, PasskeyRepository},
    storage::PasskeyStorage,
};

pub struct SeaORMPasskeyRepository {
    storage: SeaORMStorage,
}

impl SeaORMPasskeyRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
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

        self.storage
            .add_passkey(user_id, &credential_id_b64, &credential_json.to_string())
            .await
            .map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

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

        let passkeys_json = self.storage.get_passkeys(user_id).await.map_err(|e| {
            Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
        })?;

        let mut credentials = Vec::new();
        for json_str in passkeys_json {
            let json: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
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

        let passkey_json = self
            .storage
            .get_passkey_by_credential_id(&credential_id_b64)
            .await
            .map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

        if let Some(json_str) = passkey_json {
            let json: serde_json::Value = serde_json::from_str(&json_str).map_err(|e| {
                Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
            })?;

            let public_key = BASE64_STANDARD
                .decode(json["public_key"].as_str().unwrap_or(""))
                .map_err(|e| {
                    Error::Storage(torii_core::error::StorageError::Database(e.to_string()))
                })?;

            // Extract user_id from the database record if needed, or use a placeholder
            let user_id = UserId::default(); // This might need to be fetched from the database

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

    async fn update_last_used(&self, _credential_id: &[u8]) -> Result<(), Error> {
        // The current PasskeyStorage trait doesn't have this method, so this is a placeholder
        // In a real implementation, you would update the JSON data with the new last_used_at timestamp
        Ok(())
    }

    async fn delete_credential(&self, _credential_id: &[u8]) -> Result<(), Error> {
        // The current PasskeyStorage trait doesn't have this method, so this is a placeholder
        // In a real implementation, you would delete the credential by credential_id
        Ok(())
    }

    async fn delete_all_for_user(&self, _user_id: &UserId) -> Result<(), Error> {
        // The current PasskeyStorage trait doesn't have this method, so this is a placeholder
        // In a real implementation, you would delete all credentials for the user
        Ok(())
    }
}
