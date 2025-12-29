//! SeaORM user types

use torii_core::{User as ToriiUser, UserId};

use crate::entities::user;

impl From<user::Model> for ToriiUser {
    fn from(user: user::Model) -> Self {
        Self {
            id: UserId::new(&user.id),
            name: user.name.to_owned(),
            email: user.email.to_owned(),
            email_verified_at: user.email_verified_at.to_owned(),
            locked_at: user.locked_at.to_owned(),
            created_at: user.created_at.to_owned(),
            updated_at: user.updated_at.to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::SeaORMStorage;
    use crate::repositories::SeaORMUserRepository;
    use sea_orm::{Database, DatabaseConnection};

    use tokio::sync::OnceCell;
    use torii_core::repositories::UserRepository;
    use torii_core::{UserId, storage::NewUser};

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
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .name("Test User".to_string())
            .build()
            .unwrap();

        let result = user_repo.create(new_user).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo.create(new_user).await.unwrap();

        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_not_found() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let user_id = UserId::new_random();

        let result = user_repo.find_by_id(&user_id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let _ = user_repo.create(new_user).await.unwrap();

        let result = user_repo.find_by_email("test@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_user_by_email_not_found() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());

        let result = user_repo.find_by_email("nonexistent@example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_existing() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo.create(new_user).await.unwrap();

        let result = user_repo.find_or_create_by_email("test@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.id, created_user.id);
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_get_or_create_user_by_email_new() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());

        let result = user_repo.find_or_create_by_email("new@example.com").await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "new@example.com");
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_delete_user() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo.create(new_user).await.unwrap();

        let result = user_repo.delete(&created_user.id).await;
        assert!(result.is_ok());

        // Verify user is deleted
        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    #[ignore = "requires database setup"]
    async fn test_set_user_email_verified() {
        let storage = setup_test_storage().await;
        let user_repo = SeaORMUserRepository::new(storage.pool.clone());
        let new_user = NewUser::builder()
            .email("test@example.com".to_string())
            .build()
            .unwrap();

        let created_user = user_repo.create(new_user).await.unwrap();

        let result = user_repo.mark_email_verified(&created_user.id).await;
        assert!(result.is_ok());

        // Verify email is marked as verified
        let result = user_repo.find_by_id(&created_user.id).await;
        assert!(result.is_ok());

        let user = result.unwrap().unwrap();
        assert!(user.email_verified_at.is_some());
    }
}
