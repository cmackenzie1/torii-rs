use async_trait::async_trait;
use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use torii_core::{Error, User, UserId, UserStatus, repositories::UserRepository, storage::NewUser};

use crate::SeaORMStorageError;
use crate::entities::user;

pub struct SeaORMUserRepository {
    pool: DatabaseConnection,
}

impl SeaORMUserRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }

    /// Helper method to create a user with name (convenience wrapper)
    pub async fn create_user(&self, email: &str, name: Option<&str>) -> Result<User, Error> {
        let new_user = NewUser {
            id: UserId::new_random(),
            email: email.to_string(),
            name: name.map(|s| s.to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        <Self as UserRepository>::create(self, new_user).await
    }
}

#[async_trait]
impl UserRepository for SeaORMUserRepository {
    async fn create(&self, new_user: NewUser) -> Result<User, Error> {
        let user_model = user::ActiveModel {
            id: Set(new_user.id.to_string()),
            email: Set(new_user.email),
            name: Set(new_user.name),
            email_verified_at: Set(new_user.email_verified_at),
            ..Default::default()
        };

        let result = user_model
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(result.into())
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        let result = user::Entity::find_by_id(id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(result.map(|u| u.into()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        let result = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(result.map(|u| u.into()))
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        // Note: There is a potential TOCTOU race condition here between find and create.
        // If two concurrent requests call this method for the same email, both may pass the
        // existence check and attempt to create the user, causing one to fail with a unique
        // constraint violation. This is acceptable for this use case as the caller can retry.

        // First try to find the user
        let existing = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(user) = existing {
            return Ok(user.into());
        }

        // User doesn't exist, create a new one
        let new_user = NewUser {
            id: UserId::new_random(),
            email: email.to_string(),
            name: None,
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        <Self as UserRepository>::create(self, new_user).await
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        let mut existing: user::ActiveModel = user::Entity::find_by_id(user.id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .ok_or(SeaORMStorageError::UserNotFound)?
            .into();

        existing.email = Set(user.email.clone());
        existing.name = Set(user.name.clone());
        existing.email_verified_at = Set(user.email_verified_at);
        existing.locked_at = Set(user.locked_at);

        let result = existing
            .update(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(result.into())
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        user::Entity::delete_by_id(id.as_str())
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        let existing: Option<user::ActiveModel> = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(|u| u.into());

        if let Some(mut user) = existing {
            user.email_verified_at = Set(Some(Utc::now()));
            user.update(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;
            Ok(())
        } else {
            Err(SeaORMStorageError::UserNotFound.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_create_user() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let result = repo.create(new_user).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
        assert!(user.email_verified_at.is_none());
    }

    #[tokio::test]
    async fn test_find_by_id() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let created_user = repo.create(new_user).await.unwrap();
        let found_user = repo.find_by_id(&created_user.id).await.unwrap();

        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().id, created_user.id);
    }

    #[tokio::test]
    async fn test_find_by_id_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let non_existent_id = UserId::new_random();
        let result = repo.find_by_id(&non_existent_id).await.unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_find_by_email() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let _created_user = repo.create(new_user).await.unwrap();
        let found_user = repo.find_by_email("test@example.com").await.unwrap();

        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn test_find_by_email_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let result = repo.find_by_email("nonexistent@example.com").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_find_or_create_by_email_existing() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let created_user = repo.create(new_user).await.unwrap();
        let found_user = repo
            .find_or_create_by_email("test@example.com")
            .await
            .unwrap();

        assert_eq!(found_user.id, created_user.id);
        assert_eq!(found_user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_find_or_create_by_email_new() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let user = repo
            .find_or_create_by_email("new@example.com")
            .await
            .unwrap();

        assert_eq!(user.email, "new@example.com");
        assert!(user.name.is_none());
        assert!(user.email_verified_at.is_none());
    }

    #[tokio::test]
    async fn test_update_user() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let mut user = repo.create(new_user).await.unwrap();
        user.name = Some("Updated Name".to_string());
        user.email_verified_at = Some(Utc::now());

        let updated_user = repo.update(&user).await.unwrap();

        assert_eq!(updated_user.name, Some("Updated Name".to_string()));
        assert!(updated_user.email_verified_at.is_some());
    }

    #[tokio::test]
    async fn test_delete_user() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let user = repo.create(new_user).await.unwrap();
        let result = repo.delete(&user.id).await;

        assert!(result.is_ok());

        let found_user = repo.find_by_id(&user.id).await.unwrap();
        assert!(found_user.is_none());
    }

    #[tokio::test]
    async fn test_mark_email_verified() {
        let pool = setup_test_db().await;
        let repo = SeaORMUserRepository::new(pool);

        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
            status: UserStatus::Active,
            invited_by: None,
        };

        let user = repo.create(new_user).await.unwrap();
        assert!(user.email_verified_at.is_none());

        let result = repo.mark_email_verified(&user.id).await;
        assert!(result.is_ok());

        let updated_user = repo.find_by_id(&user.id).await.unwrap().unwrap();
        assert!(updated_user.email_verified_at.is_some());
    }
}
