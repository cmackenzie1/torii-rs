use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use torii_core::session::SessionId;
use torii_core::{Session, SessionStorage, UserId};

use crate::SeaORMStorage;
use crate::entities::session;

impl From<session::Model> for Session {
    fn from(value: session::Model) -> Self {
        Self {
            id: SessionId::new(&value.id),
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
    type Error = sea_orm::DbErr;

    async fn create_session(
        &self,
        session: &Session,
    ) -> Result<Session, <Self as SessionStorage>::Error> {
        let s = session::ActiveModel {
            // TODO: The id should be set by the database (or in ActiveModelBehavior)
            id: Set(session.id.as_str().to_owned()),
            user_id: Set(session.user_id.to_string()),
            token: Set(session.id.as_str().to_owned()),
            ip_address: Set(session.ip_address.to_owned()),
            user_agent: Set(session.user_agent.to_owned()),
            expires_at: Set(session.expires_at.to_owned()),
            ..Default::default()
        };

        let result = s.insert(&self.pool).await?;

        Ok(result.into())
    }

    async fn get_session(
        &self,
        id: &SessionId,
    ) -> Result<Option<Session>, <Self as SessionStorage>::Error> {
        let session = session::Entity::find_by_id(id.as_str())
            .one(&self.pool)
            .await?
            .map(|s| s.into());

        Ok(session)
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), <Self as SessionStorage>::Error> {
        session::Entity::delete_by_id(id.as_str())
            .exec(&self.pool)
            .await?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), <Self as SessionStorage>::Error> {
        session::Entity::delete_many()
            .filter(session::Column::ExpiresAt.lt(Utc::now()))
            .exec(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete_sessions_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<(), <Self as SessionStorage>::Error> {
        session::Entity::delete_many()
            .filter(session::Column::UserId.eq(user_id.as_str()))
            .exec(&self.pool)
            .await?;

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
        assert_eq!(created_session.id, session.id);
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
        assert_eq!(created_session.id, session.id);
        assert_eq!(created_session.user_id, session.user_id);
        assert_eq!(created_session.user_agent, session.user_agent);
        assert_eq!(created_session.ip_address, session.ip_address);

        let retrieved_session = storage.get_session(&session.id).await.unwrap().unwrap();
        assert_eq!(retrieved_session.id, session.id);
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
        assert_eq!(created_session.id, session.id);
        assert_eq!(created_session.user_id, session.user_id);
        assert_eq!(created_session.user_agent, session.user_agent);
        assert_eq!(created_session.ip_address, session.ip_address);

        storage.delete_session(&session.id).await.unwrap();

        let retrieved_session = storage.get_session(&session.id).await.unwrap();
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
                .get_session(&valid_session.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_session(&expired_session.id)
                .await
                .unwrap()
                .is_some()
        );

        // Run cleanup
        storage.cleanup_expired_sessions().await.unwrap();

        // Verify expired session was removed but valid session remains
        assert!(
            storage
                .get_session(&valid_session.id)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get_session(&expired_session.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
