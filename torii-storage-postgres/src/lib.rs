//! PostgreSQL storage backend for Torii
//!
//! This crate provides a PostgreSQL-based storage implementation for the Torii authentication framework.
//! It includes implementations for all repository traits and provides a complete authentication
//! storage solution using PostgreSQL as the underlying database.
//!
//! # Features
//!
//! - **User Management**: Store and retrieve user accounts with email verification support
//! - **Session Management**: Handle user sessions with configurable expiration
//! - **Password Authentication**: Secure password hashing and verification
//! - **OAuth Integration**: Store OAuth account connections and tokens
//! - **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
//! - **Database Migrations**: Automatic schema management and upgrades
//! - **Production Ready**: Designed for high-performance production workloads
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_storage_postgres::PostgresRepositoryProvider;
//! use sqlx::PgPool;
//! use torii_core::repositories::RepositoryProvider;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to PostgreSQL database
//!     let pool = PgPool::connect("postgresql://user:password@localhost/torii").await?;
//!     let repositories = std::sync::Arc::new(PostgresRepositoryProvider::new(pool));
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
//! # Database Schema
//!
//! The PostgreSQL schema includes tables for:
//! - `users` - User accounts and profile information
//! - `sessions` - Active user sessions
//! - `oauth_accounts` - Connected OAuth accounts
//! - `passkeys` - WebAuthn passkey credentials
//! - `passkey_challenges` - Temporary passkey challenges
//! - `failed_login_attempts` - Brute force protection tracking
//!
//! All tables include appropriate indexes and constraints for optimal query performance and data integrity.

mod migrations;
mod oauth;
mod passkey;
mod password;
pub mod repositories;
mod session;

pub use repositories::PostgresBruteForceRepository;
pub use repositories::PostgresRepositoryProvider;

use chrono::DateTime;
use chrono::Utc;
use migrations::AddLockedAtToUsers;
use migrations::AddPasskeyMetadata;
use migrations::CreateFailedLoginAttemptsTable;
use migrations::CreateIndexes;
use migrations::CreateOAuthAccountsTable;
use migrations::CreateOAuthStateTable;
use migrations::CreatePasskeyChallengesTable;
use migrations::CreatePasskeysTable;
use migrations::CreateSecureTokensTable;
use migrations::CreateSessionsTable;
use migrations::CreateUsersTable;
use migrations::PostgresMigrationManager;
use sqlx::PgPool;
use torii_core::error::StorageError;
use torii_core::{User, UserId};
use torii_migration::Migration;
use torii_migration::MigrationManager;

#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pub(crate) pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPool::connect(database_url).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to connect to database");
            StorageError::Database("Failed to connect to database".to_string())
        })?;

        Ok(Self::new(pool))
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        let manager = PostgresMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            StorageError::Migration("Failed to initialize migrations".to_string())
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
            Box::new(CreateOAuthStateTable),
            Box::new(CreateSecureTokensTable),
            Box::new(AddPasskeyMetadata),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            StorageError::Migration("Failed to run migrations".to_string())
        })?;

        Ok(())
    }

    /// Create a repository provider from this storage instance
    pub fn into_repository_provider(self) -> PostgresRepositoryProvider {
        PostgresRepositoryProvider::new(self.pool)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresUser {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub locked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PostgresUser> for User {
    fn from(user: PostgresUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at)
            .locked_at(user.locked_at)
            .created_at(user.created_at)
            .updated_at(user.updated_at)
            .build()
            .unwrap()
    }
}

impl From<User> for PostgresUser {
    fn from(user: User) -> Self {
        PostgresUser {
            id: user.id.into_inner(),
            email: user.email,
            name: user.name,
            email_verified_at: user.email_verified_at,
            locked_at: user.locked_at,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::repositories::{PostgresSessionRepository, PostgresUserRepository};
    use rand::Rng;
    use sqlx::types::chrono::Utc;
    use std::time::Duration;
    use torii_core::Session;
    use torii_core::repositories::{SessionRepository, UserRepository};
    use torii_core::session::SessionToken;
    use torii_core::storage::NewUser;

    pub(crate) async fn setup_test_db() -> PostgresStorage {
        // TODO: this function is leaking postgres databases after the test is done.
        // We should find a way to clean up the database after the test is done.

        let _ = tracing_subscriber::fmt().try_init();

        let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/postgres")
            .await
            .expect("Failed to create pool");

        let db_name = format!("torii_test_{}", rand::rng().random_range(1..i64::MAX));

        // Drop the database if it exists
        sqlx::query(format!("DROP DATABASE IF EXISTS {db_name}").as_str())
            .execute(&pool)
            .await
            .expect("Failed to drop database");

        // Create a new database for the test
        sqlx::query(format!("CREATE DATABASE {db_name}").as_str())
            .execute(&pool)
            .await
            .expect("Failed to create database");

        let pool = PgPool::connect(
            format!("postgres://postgres:postgres@localhost:5432/{db_name}").as_str(),
        )
        .await
        .expect("Failed to create pool");

        let storage = PostgresStorage::new(pool);
        storage.migrate().await.expect("Failed to run migrations");
        storage
    }

    pub(crate) async fn create_test_user(
        storage: &PostgresStorage,
        id: &UserId,
    ) -> Result<User, torii_core::Error> {
        let user_repo = PostgresUserRepository::new(storage.pool.clone());
        user_repo
            .create(
                NewUser::builder()
                    .id(id.clone())
                    .email(format!("test{id}@example.com"))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
    }

    pub(crate) async fn create_test_session(
        storage: &PostgresStorage,
        session_token: &SessionToken,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let session_repo = PostgresSessionRepository::new(storage.pool.clone());
        let now = Utc::now();
        session_repo
            .create(
                Session::builder()
                    .token(session_token.clone())
                    .user_id(user_id.clone())
                    .user_agent(Some("test".to_string()))
                    .ip_address(Some("127.0.0.1".to_string()))
                    .created_at(now)
                    .updated_at(now)
                    .expires_at(now + expires_in)
                    .build()
                    .expect("Failed to build session"),
            )
            .await
    }
}
