use crate::PostgresStorage;
use async_trait::async_trait;
use torii_core::{
    Error, User, UserId,
    repositories::UserRepository,
    storage::{NewUser, UserStorage},
};

pub struct PostgresUserRepository {
    storage: PostgresStorage,
}

impl PostgresUserRepository {
    pub fn new(storage: PostgresStorage) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        self.storage.create_user(&user).await
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        self.storage.get_user(id).await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.storage.get_user_by_email(email).await
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        self.storage.get_or_create_user_by_email(email).await
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        self.storage.update_user(user).await
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        self.storage.delete_user(id).await
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage.set_user_email_verified(user_id).await
    }
}
