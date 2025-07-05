use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    UserId, Error,
    repositories::{PasskeyRepository, PasskeyCredential},
};
use crate::SeaORMStorage;

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
        self.storage.add_passkey_credential(user_id, credential_id, public_key, name).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn get_credentials_for_user(&self, user_id: &UserId) -> Result<Vec<PasskeyCredential>, Error> {
        self.storage.get_passkey_credentials_for_user(user_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<PasskeyCredential>, Error> {
        self.storage.get_passkey_credential(credential_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error> {
        self.storage.update_passkey_last_used(credential_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
        self.storage.delete_passkey_credential(credential_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage.delete_all_passkey_credentials_for_user(user_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}