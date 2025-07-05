use crate::SeaORMStorage;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, Session, UserId, repositories::SessionRepository, session::SessionToken,
    storage::SessionStorage,
};

pub struct SeaORMSessionRepository {
    storage: SeaORMStorage,
}

impl SeaORMSessionRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl SessionRepository for SeaORMSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        self.storage
            .create_session(&session)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        self.storage
            .get_session(token)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        self.storage
            .delete_session(token)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage
            .delete_sessions_for_user(user_id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        self.storage
            .cleanup_expired_sessions()
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}
