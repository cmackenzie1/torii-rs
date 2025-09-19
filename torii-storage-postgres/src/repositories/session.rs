use crate::PostgresStorage;
use async_trait::async_trait;
use torii_core::{
    Error, Session, SessionStorage, UserId, repositories::SessionRepository, session::SessionToken,
};

pub struct PostgresSessionRepository {
    storage: PostgresStorage,
}

impl PostgresSessionRepository {
    pub fn new(storage: PostgresStorage) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        self.storage.create_session(&session).await
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        self.storage.get_session(token).await
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        self.storage.delete_session(token).await
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage.delete_sessions_for_user(user_id).await
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        self.storage.cleanup_expired_sessions().await
    }
}
