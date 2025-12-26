use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use torii_core::session::SessionToken;
use torii_core::{Session, SessionStorage, UserId};

use crate::entities::session;
use crate::{SeaORMStorage, SeaORMStorageError};

/// Convert a database session model to a Session.
///
/// Note: The token field in the database stores the hash, not the plaintext.
/// When loading from storage, we create a "placeholder" token that contains the hash.
/// This allows verification via constant-time comparison, but the original
/// plaintext token is not recoverable (by design).
impl From<session::Model> for Session {
    fn from(value: session::Model) -> Self {
        // The database stores the hash in the 'token' column
        // We create a placeholder token - actual verification should use verify_hash
        Self {
            token: SessionToken::new(&value.token),
            token_hash: value.token.clone(),
            user_id: UserId::new(&value.user_id),
            user_agent: value.user_agent.to_owned(),
            ip_address: value.ip_address.to_owned(),
            created_at: value.created_at.to_owned(),
            updated_at: value.updated_at.to_owned(),
            expires_at: value.expires_at.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl SessionStorage for SeaORMStorage {
    async fn create_session(&self, session: &Session) -> Result<Session, torii_core::Error> {
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

    async fn get_session(
        &self,
        token: &SessionToken,
    ) -> Result<Option<Session>, torii_core::Error> {
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

    async fn delete_session(&self, token: &SessionToken) -> Result<(), torii_core::Error> {
        // Compute the hash of the provided token for deletion
        let token_hash = token.token_hash();

        session::Entity::delete_many()
            .filter(session::Column::Token.eq(&token_hash))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), torii_core::Error> {
        session::Entity::delete_many()
            .filter(session::Column::ExpiresAt.lt(Utc::now()))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), torii_core::Error> {
        session::Entity::delete_many()
            .filter(session::Column::UserId.eq(user_id.as_str()))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    use crate::migrations::Migrator;

    use super::*;

    #[tokio::test]
    async fn test_create_session() {
        let storage = SeaORMStorage::new(Database::connect("sqlite::memory:").await.unwrap());
        Migrator::up(&storage.pool, None).await.unwrap();

        let session = Session::builder()
            .user_id(UserId::new("1"))
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .build()
            .unwrap();

        let created_session = storage.create_session(&session).await.unwrap();
        assert_eq!(created_session.token, session.token);
        assert_eq!(created_session.user_id, session.user_id);
        assert_eq!(created_session.user_agent, session.user_agent);
        assert_eq!(created_session.ip_address, session.ip_address);
        assert_eq!(
            created_session.created_at.timestamp(),
            session.created_at.timestamp()
        );
    }

    #[tokio::test]
    async fn test_get_session() {
        let storage = SeaORMStorage::new(Database::connect("sqlite::memory:").await.unwrap());
        Migrator::up(&storage.pool, None).await.unwrap();

        let session = Session::builder()
            .user_id(UserId::new("1"))
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .build()
            .unwrap();

        let created_session = storage.create_session(&session).await.unwrap();
        assert_eq!(created_session.token, session.token);
        assert_eq!(created_session.user_id, session.user_id);
        assert_eq!(created_session.user_agent, session.user_agent);
        assert_eq!(created_session.ip_address, session.ip_address);

        let retrieved_session = storage.get_session(&session.token).await.unwrap().unwrap();
        assert_eq!(retrieved_session.token, session.token);
        assert_eq!(retrieved_session.user_id, session.user_id);
        assert_eq!(retrieved_session.user_agent, session.user_agent);
        assert_eq!(retrieved_session.ip_address, session.ip_address);
    }

    #[tokio::test]
    async fn test_delete_session() {
        let storage = SeaORMStorage::new(Database::connect("sqlite::memory:").await.unwrap());
        Migrator::up(&storage.pool, None).await.unwrap();

        let session = Session::builder()
            .user_id(UserId::new("1"))
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .build()
            .unwrap();

        let created_session = storage.create_session(&session).await.unwrap();
        assert_eq!(created_session.token, session.token);
        assert_eq!(created_session.user_id, session.user_id);
        assert_eq!(created_session.user_agent, session.user_agent);
        assert_eq!(created_session.ip_address, session.ip_address);

        storage.delete_session(&session.token).await.unwrap();

        let retrieved_session = storage.get_session(&session.token).await.unwrap();
        assert!(retrieved_session.is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        let storage = SeaORMStorage::new(Database::connect("sqlite::memory:").await.unwrap());
        Migrator::up(&storage.pool, None).await.unwrap();

        // Create valid session
        let valid_session = Session::builder()
            .user_id(UserId::new("1"))
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .expires_at(Utc::now() + chrono::Duration::days(1))
            .build()
            .unwrap();
        storage.create_session(&valid_session).await.unwrap();

        // Create expired session
        let expired_session = Session::builder()
            .user_id(UserId::new("1"))
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .expires_at(Utc::now() - chrono::Duration::days(1))
            .build()
            .unwrap();
        storage.create_session(&expired_session).await.unwrap();

        // Verify both sessions exist
        assert!(
            storage
                .get_session(&valid_session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_session(&expired_session.token)
                .await
                .unwrap()
                .is_some()
        );

        // Run cleanup
        storage.cleanup_expired_sessions().await.unwrap();

        // Verify expired session was removed but valid session remains
        assert!(
            storage
                .get_session(&valid_session.token)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_session(&expired_session.token)
                .await
                .unwrap()
                .is_none()
        );
    }
}
