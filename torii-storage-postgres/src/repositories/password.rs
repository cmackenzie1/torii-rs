use crate::PostgresStorage;
use async_trait::async_trait;
use torii_core::{Error, UserId, repositories::PasswordRepository, storage::PasswordStorage};

pub struct PostgresPasswordRepository {
    storage: PostgresStorage,
}

impl PostgresPasswordRepository {
    pub fn new(storage: PostgresStorage) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl PasswordRepository for PostgresPasswordRepository {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        self.storage.set_password_hash(user_id, hash).await
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        self.storage.get_password_hash(user_id).await
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage.remove_password_hash(user_id).await
    }
}
