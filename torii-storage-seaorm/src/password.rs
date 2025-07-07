use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, EntityTrait};
use torii_core::{UserId, storage::PasswordStorage};

use crate::{SeaORMStorage, SeaORMStorageError};

use crate::entities::user;

#[async_trait::async_trait]
impl PasswordStorage for SeaORMStorage {
    async fn set_password_hash(
        &self,
        user_id: &UserId,
        password_hash: &str,
    ) -> Result<(), torii_core::Error> {
        let user: Option<user::ActiveModel> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(|user| user.into());

        if user.is_none() {
            return Err(SeaORMStorageError::UserNotFound.into());
        }

        if let Some(mut user) = user {
            user.password_hash = Set(Some(password_hash.to_string()));
            user.update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
        }

        Ok(())
    }

    async fn get_password_hash(
        &self,
        user_id: &UserId,
    ) -> Result<Option<String>, torii_core::Error> {
        let user: Option<user::Model> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match user {
            Some(user) => Ok(user.password_hash),
            _ => Err(SeaORMStorageError::UserNotFound.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use torii_core::User;

    use crate::entities::user;
    use crate::migrations::Migrator;

    use super::*;

    #[tokio::test]
    async fn test_password_hash() {
        let storage = SeaORMStorage::new(
            Database::connect("sqlite::memory:")
                .await
                .expect("Failed to connect to db"),
        );
        Migrator::up(&storage.pool, None)
            .await
            .expect("Failed to run migrations");

        // Create test user
        let user = User::builder()
            .id(UserId::new("1"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build user");

        let user_model = user::ActiveModel {
            id: Set(user.id.as_str().to_owned()),
            email: Set(user.email.to_owned()),
            ..Default::default()
        };
        user_model
            .insert(&storage.pool)
            .await
            .expect("Failed to create user");

        // Set password hash
        let hash = "test_hash_123";
        storage
            .set_password_hash(&user.id, hash)
            .await
            .expect("Failed to set password hash");

        // Get password hash
        let stored_hash = storage
            .get_password_hash(&user.id)
            .await
            .expect("Failed to get password hash");

        assert_eq!(stored_hash, Some(hash.to_string()));

        // Get password hash for non-existent user
        let result = storage
            .get_password_hash(&UserId::new("non_existent"))
            .await;

        assert!(result.is_err());
    }
}
