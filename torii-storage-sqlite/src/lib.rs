mod migrations;
mod oauth;
mod passkey;
mod password;
mod session;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use migrations::CreateOAuthAccountsTable;
use migrations::CreatePasskeyChallengesTable;
use migrations::CreatePasskeysTable;
use migrations::CreateSessionsTable;
use migrations::CreateUsersTable;
use migrations::SqliteMigrationManager;
use sqlx::SqlitePool;
use torii_core::Error;
use torii_core::{
    User, UserId,
    storage::{NewUser, UserStorage},
};
use torii_migration::Migration;
use torii_migration::MigrationManager;

pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), Error> {
        let manager = SqliteMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            Error::Storage("Failed to initialize migrations".to_string())
        })?;

        let migrations: Vec<Box<dyn Migration<_>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            Error::Storage("Failed to run migrations".to_string())
        })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<i64>,
    created_at: i64,
    updated_at: i64,
}

impl From<SqliteUser> for User {
    fn from(user: SqliteUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at.map(|timestamp| {
                DateTime::from_timestamp(timestamp, 0).expect("Invalid timestamp")
            }))
            .created_at(DateTime::from_timestamp(user.created_at, 0).expect("Invalid timestamp"))
            .updated_at(DateTime::from_timestamp(user.updated_at, 0).expect("Invalid timestamp"))
            .build()
            .unwrap()
    }
}

impl From<User> for SqliteUser {
    fn from(user: User) -> Self {
        SqliteUser {
            id: user.id.into_inner(),
            email: user.email,
            name: user.name,
            email_verified_at: user
                .email_verified_at
                .map(|timestamp| timestamp.timestamp()),
            created_at: user.created_at.timestamp(),
            updated_at: user.updated_at.timestamp(),
        }
    }
}

#[async_trait]
impl UserStorage for SqliteStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        let now = Utc::now();
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            INSERT INTO users (id, email, name, email_verified_at, created_at, updated_at) 
            VALUES (?, ?, ?, ?, ?, ?)
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_ref())
        .bind(&user.email)
        .bind(&user.name)
        .bind(
            user.email_verified_at
                .map(|timestamp| timestamp.timestamp()),
        )
        .bind(now.timestamp())
        .bind(now.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            Self::Error::Storage("Failed to create user".to_string())
        })?;

        Ok(user.into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id = ?
            "#,
        )
        .bind(id.as_ref())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user");
            Self::Error::Storage("Failed to get user".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = ?
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by email");
            Self::Error::Storage("Failed to get user by email".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
        let user = self.get_user_by_email(email).await?;
        if let Some(user) = user {
            return Ok(user);
        }

        let user = self
            .create_user(
                &NewUser::builder()
                    .id(UserId::new_random())
                    .email(email.to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get or create user by email");
                Self::Error::Storage("Failed to get or create user by email".to_string())
            })?;

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> Result<User, Self::Error> {
        let now = Utc::now();
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            UPDATE users 
            SET email = ?, name = ?, email_verified_at = ?, updated_at = ? 
            WHERE id = ?
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(
            user.email_verified_at
                .map(|timestamp| timestamp.timestamp()),
        )
        .bind(now.timestamp())
        .bind(user.id.as_ref())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            Self::Error::Storage("Failed to update user".to_string())
        })?;

        Ok(user.into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.as_ref())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                Self::Error::Storage("Failed to delete user".to_string())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::{Sqlite, types::chrono::Utc};
    use torii_migration::{Migration, MigrationManager};

    use super::*;
    use crate::migrations::{
        CreateOAuthAccountsTable, CreateSessionsTable, CreateUsersTable, SqliteMigrationManager,
    };
    use crate::session::test::create_test_session;

    pub(crate) async fn setup_sqlite_storage() -> Result<SqliteStorage, sqlx::Error> {
        let _ = tracing_subscriber::fmt().try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let manager = SqliteMigrationManager::new(pool.clone());
        manager
            .initialize()
            .await
            .expect("Failed to initialize migrations");

        let migrations: Vec<Box<dyn Migration<Sqlite>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
        ];
        manager
            .up(&migrations)
            .await
            .expect("Failed to run migrations");

        Ok(SqliteStorage::new(pool))
    }

    pub(crate) async fn create_test_user(
        storage: &SqliteStorage,
        id: &str,
    ) -> Result<User, torii_core::Error> {
        storage
            .create_user(
                &NewUser::builder()
                    .id(UserId::new(id))
                    .email(format!("test{}@example.com", id))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
    }

    #[tokio::test]
    async fn test_sqlite_storage() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test1@example.com"));

        let fetched = storage
            .get_user(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test1@example.com")
        );

        storage
            .delete_user(&UserId::new("1"))
            .await
            .expect("Failed to delete user");
        let deleted = storage
            .get_user(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_timestamps_are_set_correctly() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Verify user timestamps are set
        assert!(user.created_at <= Utc::now());
        assert!(user.updated_at <= Utc::now());
        assert_eq!(user.created_at, user.updated_at);

        // Create test session
        let session = create_test_session(&storage, "session1", "1", Duration::from_secs(3600))
            .await
            .expect("Failed to create session");

        // Verify session timestamps are set
        assert!(session.created_at <= Utc::now());
        assert!(session.updated_at <= Utc::now());
        assert_eq!(session.created_at, session.updated_at);
        assert!(session.expires_at > Utc::now());

        // Update user

        tokio::time::sleep(Duration::from_secs(1)).await; // Need to sleep for at least 1 second to ensure the updated_at is different

        let mut updated_user = user.clone();
        updated_user.name = Some("Test User".to_string());
        let updated_user = storage
            .update_user(&updated_user)
            .await
            .expect("Failed to update user");

        // Verify updated timestamps
        assert_eq!(updated_user.created_at, user.created_at);
        assert!(updated_user.updated_at > user.updated_at);
    }
}
