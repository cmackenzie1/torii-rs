use chrono::Utc;
use sea_orm::ColumnTrait;
use sea_orm::QueryFilter;
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use torii_core::{NewUser, User as ToriiUser, UserId, UserStorage};

use crate::entities::user;
use crate::{SeaORMStorage, SeaORMStorageError};

impl From<user::Model> for ToriiUser {
    fn from(user: user::Model) -> Self {
        Self {
            id: UserId::new(&user.id),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            email_verified_at: user.email_verified_at.to_owned(),
            created_at: user.created_at.to_owned(),
            updated_at: user.updated_at.to_owned(),
        }
    }
}

#[async_trait::async_trait]
impl UserStorage for SeaORMStorage {
    async fn create_user(&self, user: &NewUser) -> Result<ToriiUser, torii_core::Error> {
        let model = user::ActiveModel {
            email: Set(user.email.to_owned()),
            name: Set(user.name.to_owned()),
            email_verified_at: Set(user.email_verified_at.to_owned()),
            ..Default::default()
        };

        Ok(model
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<ToriiUser>, torii_core::Error> {
        let user = user::Entity::find_by_id(id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(user.map(ToriiUser::from))
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<ToriiUser>, torii_core::Error> {
        Ok(user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .map(ToriiUser::from))
    }

    async fn get_or_create_user_by_email(
        &self,
        email: &str,
    ) -> Result<ToriiUser, torii_core::Error> {
        let user = self.get_user_by_email(email).await?;

        match user {
            Some(user) => Ok(user),
            None => {
                self.create_user(&NewUser::builder().email(email.to_string()).build().unwrap())
                    .await
            }
        }
    }

    async fn update_user(&self, user: &ToriiUser) -> Result<ToriiUser, torii_core::Error> {
        let model = user::ActiveModel {
            id: Set(user.id.as_str().to_string()),
            name: Set(user.name.to_owned()),
            email: Set(user.email.to_owned()),
            email_verified_at: Set(user.email_verified_at.to_owned()),
            updated_at: Set(Utc::now()),
            ..Default::default()
        };

        Ok(model
            .update(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), torii_core::Error> {
        let _ = user::Entity::delete_by_id(id.as_str())
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }

    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), torii_core::Error> {
        let mut user: user::ActiveModel = user::Entity::find_by_id(user_id.as_str())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?
            .unwrap()
            .into();

        user.email_verified_at = Set(Some(Utc::now()));
        user.update(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use crate::SeaORMStorage;
    use sea_orm::{Database, DatabaseConnection};

    use tokio::sync::OnceCell;
    use torii_core::{NewUser, UserId, UserStorage};

    static TEST_DB: OnceCell<DatabaseConnection> = OnceCell::const_new();

    async fn get_test_db() -> &'static DatabaseConnection {
        TEST_DB
            .get_or_init(|| async {
                let database_url =
                    std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite::memory:".to_string());

                Database::connect(&database_url)
                    .await
                    .expect("Failed to connect to test database")
            })
            .await
    }

    async fn setup_test_storage() -> SeaORMStorage {
        let db = get_test_db().await.clone();

        // Create test user table using raw SQL for simplicity
        let create_table = r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY DEFAULT (hex(randomblob(16))),
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                email_verified_at DATETIME,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        "#;

        use sea_orm::{ConnectionTrait, Statement};
        let _ = db
            .execute(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                create_table.to_string(),
            ))
            .await;

        SeaORMStorage::new(db)
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_create_user() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .name("Test User".to_string())
            .build()
            .unwrap();

        let result = storage.create_user(&new_user).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = storage.create_user(&new_user).await.unwrap();

        let result = storage.get_user(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_not_found() {
        let storage = setup_test_storage().await;
        let user_id = UserId::new_random();

        let result = storage.get_user(&user_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let _ = storage.create_user(&new_user).await.unwrap();

        let result = storage.get_user_by_email("test@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email_not_found() {
        let storage = setup_test_storage().await;

        let result = storage.get_user_by_email("nonexistent@example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_existing() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = storage.create_user(&new_user).await.unwrap();

        let result = storage
            .get_or_create_user_by_email("test@example.com")
            .await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.id, created_user.id);
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_new() {
        let storage = setup_test_storage().await;

        let result = storage.get_or_create_user_by_email("new@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "new@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_delete_user() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = storage.create_user(&new_user).await.unwrap();

        let result = storage.delete_user(&created_user.id).await;
        assert!(result.is_ok());

        // Verify user is deleted
        let result = storage.get_user(&created_user.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_set_user_email_verified() {
        let storage = setup_test_storage().await;
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = storage.create_user(&new_user).await.unwrap();

        let result = storage.set_user_email_verified(&created_user.id).await;
        assert!(result.is_ok());

        // Verify email is marked as verified
        let result = storage.get_user(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap().unwrap();
        assert!(user.email_verified_at.is_some());
    }
}
