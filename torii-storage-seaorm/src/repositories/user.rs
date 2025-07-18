use crate::SeaORMStorage;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, User, UserId,
    repositories::UserRepository,
    storage::{NewUser, UserStorage},
};

pub struct SeaORMUserRepository {
    storage: SeaORMStorage,
}

impl SeaORMUserRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl UserRepository for SeaORMUserRepository {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        self.storage
            .create_user(&user)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        self.storage
            .get_user(id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.storage
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        self.storage
            .get_or_create_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        self.storage
            .update_user(user)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        self.storage
            .delete_user(id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage
            .set_user_email_verified(user_id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use chrono::Utc;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use torii_core::storage::NewUser;

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
        };

        let user = repo.create(new_user).await.unwrap();
        assert!(user.email_verified_at.is_none());

        let result = repo.mark_email_verified(&user.id).await;
        assert!(result.is_ok());

        let updated_user = repo.find_by_id(&user.id).await.unwrap().unwrap();
        assert!(updated_user.email_verified_at.is_some());
    }
}
