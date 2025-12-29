//! SQLite storage backend for Torii
//!
//! This crate provides a SQLite-based storage implementation for the Torii authentication framework.
//! It includes implementations for all repository traits and provides a complete authentication
//! storage solution using SQLite as the underlying database.
//!
//! # Features
//!
//! - **User Management**: Store and retrieve user accounts with email verification support
//! - **Session Management**: Handle user sessions with configurable expiration
//! - **Password Authentication**: Secure password hashing and verification
//! - **OAuth Integration**: Store OAuth account connections and tokens
//! - **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
//! - **Magic Link Authentication**: Generate and verify magic links for passwordless login
//! - **Database Migrations**: Automatic schema management and upgrades
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_storage_sqlite::SqliteRepositoryProvider;
//! use sqlx::SqlitePool;
//! use torii_core::repositories::RepositoryProvider;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to SQLite database
//!     let pool = SqlitePool::connect("sqlite://todos.db?mode=rwc").await?;
//!     let repositories = std::sync::Arc::new(SqliteRepositoryProvider::new(pool));
//!     
//!     // Run migrations to set up the schema
//!     repositories.migrate().await?;
//!     
//!     // Use with Torii
//!     let torii = torii::Torii::new(repositories);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Repository Provider
//!
//! The crate provides [`SqliteRepositoryProvider`] which implements the [`RepositoryProvider`] trait
//! from `torii-core`, allowing it to be used directly with the main Torii authentication coordinator.
//!
//! # Database Schema
//!
//! The SQLite schema includes tables for:
//! - `users` - User accounts and profile information
//! - `sessions` - Active user sessions
//! - `oauth_accounts` - Connected OAuth accounts
//! - `passkeys` - WebAuthn passkey credentials
//! - `passkey_challenges` - Temporary passkey challenges
//! - `failed_login_attempts` - Brute force protection tracking
//!
//! All tables include appropriate indexes for optimal query performance.

mod migrations;
mod oauth;
mod passkey;
mod password;
mod repositories;
mod session;

use chrono::DateTime;
use migrations::{
    AddLockedAtToUsers, CreateFailedLoginAttemptsTable, CreateIndexes, CreateOAuthAccountsTable,
    CreatePasskeyChallengesTable, CreatePasskeysTable, CreateSessionsTable, CreateUsersTable,
    SqliteMigrationManager,
};
use sqlx::SqlitePool;
use torii_core::error::StorageError;
use torii_core::{User, UserId};
use torii_migration::{Migration, MigrationManager};

pub use repositories::SqliteRepositoryProvider;

#[derive(Clone)]
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = SqlitePool::connect(database_url).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to connect to database");
            StorageError::Database("Failed to connect to database".to_string())
        })?;

        Ok(Self::new(pool))
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        let manager = SqliteMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            StorageError::Database("Failed to initialize migrations".to_string())
        })?;

        let migrations: Vec<Box<dyn Migration<_>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
            Box::new(CreateIndexes),
            Box::new(CreateFailedLoginAttemptsTable),
            Box::new(AddLockedAtToUsers),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            StorageError::Database("Failed to run migrations".to_string())
        })?;

        Ok(())
    }

    /// Create a repository provider from this storage instance
    pub fn into_repository_provider(self) -> SqliteRepositoryProvider {
        SqliteRepositoryProvider::new(self.pool)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<i64>,
    locked_at: Option<i64>,
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
            .locked_at(
                user.locked_at
                    .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0)),
            )
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
            locked_at: user.locked_at.map(|timestamp| timestamp.timestamp()),
            created_at: user.created_at.timestamp(),
            updated_at: user.updated_at.timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use sqlx::{Sqlite, types::chrono::Utc};
    use torii_core::{SessionToken, repositories::UserRepository, storage::NewUser};
    use torii_migration::{Migration, MigrationManager};

    use super::*;
    use crate::migrations::{
        AddLockedAtToUsers, CreateOAuthAccountsTable, CreateSessionsTable, CreateUsersTable,
        SqliteMigrationManager,
    };
    use crate::repositories::SqliteUserRepository;
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
            Box::new(AddLockedAtToUsers),
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
        let user_repo = SqliteUserRepository::new(storage.pool.clone());
        user_repo
            .create(
                NewUser::builder()
                    .id(UserId::new(id))
                    .email(format!("test{id}@example.com"))
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
        let user_repo = SqliteUserRepository::new(storage.pool.clone());

        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");
        assert_eq!(user.email, format!("test1@example.com"));

        let fetched = user_repo
            .find_by_id(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert_eq!(
            fetched.expect("User should exist").email,
            format!("test1@example.com")
        );

        user_repo
            .delete(&UserId::new("1"))
            .await
            .expect("Failed to delete user");
        let deleted = user_repo
            .find_by_id(&UserId::new("1"))
            .await
            .expect("Failed to get user");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_timestamps_are_set_correctly() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");
        let user_repo = SqliteUserRepository::new(storage.pool.clone());

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Verify user timestamps are set
        assert!(user.created_at <= Utc::now());
        assert!(user.updated_at <= Utc::now());
        assert_eq!(user.created_at, user.updated_at);

        // Create test session
        let session_token = SessionToken::new_random();
        let session = create_test_session(&storage, &session_token, "1", Duration::from_secs(3600))
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
        let updated_user = user_repo
            .update(&updated_user)
            .await
            .expect("Failed to update user");

        // Verify updated timestamps
        assert_eq!(updated_user.created_at, user.created_at);
        assert!(updated_user.updated_at > user.updated_at);
    }
}
