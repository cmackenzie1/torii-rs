use crate::SeaORMStorage;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, User, UserId,
    repositories::UserRepository,
    storage::{NewUser, UserStorage},
};

pub struct SeaORMUserRepository {
    storage: SeaORMStorage,
}

impl SeaORMUserRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl UserRepository for SeaORMUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        self.storage
            .create_user(&user)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        self.storage
            .get_user(id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.storage
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        self.storage
            .get_or_create_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        self.storage
            .update_user(user)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        self.storage
            .delete_user(id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage
            .set_user_email_verified(user_id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}
