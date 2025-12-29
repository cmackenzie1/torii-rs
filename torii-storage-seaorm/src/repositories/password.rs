use async_trait::async_trait;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait};
use torii_core::{Error, UserId, repositories::PasswordRepository};

use crate::SeaORMStorageError;
use crate::entities::user;

pub struct SeaORMPasswordRepository {
    pool: DatabaseConnection,
}

impl SeaORMPasswordRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordRepository for SeaORMPasswordRepository {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        let user: Option<user::ActiveModel> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(|user| user.into());

        if user.is_none() {
            return Err(SeaORMStorageError::UserNotFound.into());
        }

        if let Some(mut user) = user {
            user.password_hash = Set(Some(hash.to_string()));
            user.update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
        }

        Ok(())
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        let user: Option<user::Model> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match user {
            Some(user) => Ok(user.password_hash),
            _ => Err(SeaORMStorageError::UserNotFound.into()),
        }
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        let user: Option<user::ActiveModel> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(|user| user.into());

        if user.is_none() {
            return Err(SeaORMStorageError::UserNotFound.into());
        }

        if let Some(mut user) = user {
            user.password_hash = Set(None);
            user.update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::repositories::SeaORMUserRepository;
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

    #[tokio::test]
    async fn test_password_hash() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasswordRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        // Set password hash
        let hash = "test_hash_123";
        repo.set_password_hash(&user_id, hash)
            .await
            .expect("Failed to set password hash");

        // Get password hash
        let stored_hash = repo
            .get_password_hash(&user_id)
            .await
            .expect("Failed to get password hash");

        assert_eq!(stored_hash, Some(hash.to_string()));

        // Get password hash for non-existent user
        let result = repo.get_password_hash(&UserId::new("non_existent")).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_remove_password_hash() {
        let pool = setup_test_db().await;
        let repo = SeaORMPasswordRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        // Set password hash
        let hash = "test_hash_123";
        repo.set_password_hash(&user_id, hash).await.unwrap();

        // Verify it's set
        let stored_hash = repo.get_password_hash(&user_id).await.unwrap();
        assert_eq!(stored_hash, Some(hash.to_string()));

        // Remove password hash
        repo.remove_password_hash(&user_id).await.unwrap();

        // Verify it's removed
        let stored_hash = repo.get_password_hash(&user_id).await.unwrap();
        assert_eq!(stored_hash, None);
    }
}
