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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use chrono::{Duration, Utc};
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use torii_core::storage::{NewUser, UserStorage};

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    async fn create_test_user(pool: &DatabaseConnection) -> UserId {
        let storage = SeaORMStorage::new(pool.clone());
        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
        };

        let user = storage.create_user(&new_user).await.unwrap();
        user.id
    }

    fn create_test_session(user_id: &UserId) -> Session {
        let expires_at = Utc::now() + Duration::hours(1);

        Session {
            token: SessionToken::new_random(),
            user_id: user_id.clone(),
            expires_at,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
        }
    }

    #[tokio::test]
    async fn test_create_session() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let session = create_test_session(&user_id);
        let original_token = session.token.clone();

        let result = repo.create(session).await;
        assert!(result.is_ok());

        let created_session = result.unwrap();
        assert_eq!(created_session.token, original_token);
        assert_eq!(created_session.user_id, user_id);
    }

    #[tokio::test]
    async fn test_find_by_token() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let session = create_test_session(&user_id);
        let token = session.token.clone();

        let _created_session = repo.create(session).await.unwrap();

        let found_session = repo.find_by_token(&token).await.unwrap();
        assert!(found_session.is_some());

        let found_session = found_session.unwrap();
        assert_eq!(found_session.token, token);
        assert_eq!(found_session.user_id, user_id);
    }

    #[tokio::test]
    async fn test_find_by_token_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool);

        let non_existent_token = SessionToken::new_random();
        let result = repo.find_by_token(&non_existent_token).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_session() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let session = create_test_session(&user_id);
        let token = session.token.clone();

        let _created_session = repo.create(session).await.unwrap();

        let result = repo.delete(&token).await;
        assert!(result.is_ok());

        let found_session = repo.find_by_token(&token).await.unwrap();
        assert!(found_session.is_none());
    }

    #[tokio::test]
    async fn test_delete_by_user_id() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let session1 = create_test_session(&user_id);
        let session2 = create_test_session(&user_id);
        let token1 = session1.token.clone();
        let token2 = session2.token.clone();

        let _created_session1 = repo.create(session1).await.unwrap();
        let _created_session2 = repo.create(session2).await.unwrap();

        let result = repo.delete_by_user_id(&user_id).await;
        assert!(result.is_ok());

        let found_session1 = repo.find_by_token(&token1).await.unwrap();
        let found_session2 = repo.find_by_token(&token2).await.unwrap();

        assert!(found_session1.is_none());
        assert!(found_session2.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let pool = setup_test_db().await;
        let repo = SeaORMSessionRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let expired_session = Session {
            token: SessionToken::new_random(),
            user_id: user_id.clone(),
            expires_at: Utc::now() - Duration::hours(1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ip_address: None,
            user_agent: None,
        };

        let valid_session = create_test_session(&user_id);
        let expired_token = expired_session.token.clone();
        let valid_token = valid_session.token.clone();

        let _created_expired = repo.create(expired_session).await.unwrap();
        let _created_valid = repo.create(valid_session).await.unwrap();

        let result = repo.cleanup_expired().await;
        assert!(result.is_ok());

        let found_expired = repo.find_by_token(&expired_token).await.unwrap();
        let found_valid = repo.find_by_token(&valid_token).await.unwrap();

        assert!(found_expired.is_none());
        assert!(found_valid.is_some());
    }
}
