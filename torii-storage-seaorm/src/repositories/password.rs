use crate::SeaORMStorage;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{Error, UserId, repositories::PasswordRepository, storage::PasswordStorage};

pub struct SeaORMPasswordRepository {
    storage: SeaORMStorage,
}

impl SeaORMPasswordRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl PasswordRepository for SeaORMPasswordRepository {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        self.storage
            .set_password_hash(user_id, hash)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        self.storage
            .get_password_hash(user_id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        // For SeaORM, we can set the password hash to None to "remove" it
        self.storage
            .set_password_hash(user_id, "")
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}
