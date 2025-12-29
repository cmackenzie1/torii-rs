use async_trait::async_trait;
use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use torii_core::{Error, Session, UserId, repositories::SessionRepository, session::SessionToken};

use crate::SeaORMStorageError;
use crate::entities::session;

pub struct SeaORMSessionRepository {
    pool: DatabaseConnection,
}

impl SeaORMSessionRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SeaORMSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        // Store the hash, not the plaintext token
        let s = session::ActiveModel {
            user_id: Set(session.user_id.to_string()),
            token: Set(session.token_hash.clone()), // Store hash, not plaintext
            ip_address: Set(session.ip_address.to_owned()),
            user_agent: Set(session.user_agent.to_owned()),
            expires_at: Set(session.expires_at.to_owned()),
            ..Default::default()
        };

        let result = s
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        // Return the original session with its plaintext token
        // (the caller already has it)
        Ok(Session {
            token: session.token.clone(),
            token_hash: session.token_hash.clone(),
            user_id: session.user_id.clone(),
            user_agent: result.user_agent,
            ip_address: result.ip_address,
            created_at: result.created_at,
            updated_at: result.updated_at,
            expires_at: result.expires_at,
        })
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        // Compute the hash of the provided token for lookup
        let token_hash = token.token_hash();

        let session = session::Entity::find()
            .filter(session::Column::Token.eq(&token_hash))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(s) = session {
            // Verify using constant-time comparison
            if token.verify_hash(&s.token) {
                return Ok(Some(Session {
                    token: token.clone(),
                    token_hash: s.token,
                    user_id: UserId::new(&s.user_id),
                    user_agent: s.user_agent,
                    ip_address: s.ip_address,
                    created_at: s.created_at,
                    updated_at: s.updated_at,
                    expires_at: s.expires_at,
                }));
            }
        }

        Ok(None)
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        // Compute the hash of the provided token for deletion
        let token_hash = token.token_hash();

        session::Entity::delete_many()
            .filter(session::Column::Token.eq(&token_hash))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        session::Entity::delete_many()
            .filter(session::Column::UserId.eq(user_id.as_str()))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        session::Entity::delete_many()
            .filter(session::Column::ExpiresAt.lt(Utc::now()))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::repositories::SeaORMUserRepository;
    use chrono::Duration;
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

    fn create_test_session(user_id: &UserId) -> Session {
        let expires_at = Utc::now() + Duration::hours(1);

        Session::builder()
            .token(SessionToken::new_random())
            .user_id(user_id.clone())
            .expires_at(expires_at)
            .build()
            .unwrap()
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

        let expired_session = Session::builder()
            .token(SessionToken::new_random())
            .user_id(user_id.clone())
            .expires_at(Utc::now() - Duration::hours(1))
            .build()
            .unwrap();

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
