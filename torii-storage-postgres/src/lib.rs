//! PostgreSQL storage backend for Torii
//!
//! This crate provides a PostgreSQL-based storage implementation for the Torii authentication framework.
//! It includes implementations for all core storage traits and provides a complete authentication
//! storage solution using PostgreSQL as the underlying database.
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
//! - **Production Ready**: Designed for high-performance production workloads
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_storage_postgres::PostgresStorage;
//! use torii_core::UserId;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to PostgreSQL database
//!     let storage = PostgresStorage::connect("postgresql://user:password@localhost/torii").await?;
//!     
//!     // Run migrations to set up the schema
//!     storage.migrate().await?;
//!     
//!     // Use with Torii (PostgresRepositoryProvider not yet implemented)
//!     // let repositories = std::sync::Arc::new(storage.into_repository_provider());
//!     // let torii = torii::Torii::new(repositories);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Current Status
//!
//! This crate currently provides the base PostgreSQL storage implementation with user and session
//! management. The full repository provider implementation is still in development.
//!
//! # Storage Implementations
//!
//! This crate implements the following storage traits:
//! - [`UserStorage`](torii_core::storage::UserStorage) - User account management
//! - [`SessionStorage`](torii_core::storage::SessionStorage) - Session management
//! - Password repository for secure password storage
//! - OAuth repository for third-party authentication
//! - Passkey repository for WebAuthn support
//! - Magic link repository for passwordless authentication
//!
//! # Database Schema
//!
//! The PostgreSQL schema includes tables for:
//! - `users` - User accounts and profile information
//! - `sessions` - Active user sessions
//! - `passwords` - Hashed password credentials
//! - `oauth_accounts` - Connected OAuth accounts
//! - `passkeys` - WebAuthn passkey credentials
//! - `passkey_challenges` - Temporary passkey challenges
//! - `magic_links` - Magic link tokens and metadata
//!
//! All tables include appropriate indexes and constraints for optimal query performance and data integrity.

mod magic_link;
mod migrations;
mod oauth;
mod passkey;
mod password;
mod session;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use migrations::CreateIndexes;
use migrations::CreateMagicLinksTable;
use migrations::CreateOAuthAccountsTable;
use migrations::CreatePasskeyChallengesTable;
use migrations::CreatePasskeysTable;
use migrations::CreateSessionsTable;
use migrations::CreateUsersTable;
use migrations::PostgresMigrationManager;
use sqlx::PgPool;
use torii_core::error::StorageError;
use torii_core::{
    User, UserId,
    storage::{NewUser, UserStorage},
};
use torii_migration::Migration;
use torii_migration::MigrationManager;

#[derive(Debug, Clone)]
pub struct PostgresStorage {
    pool: PgPool,
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
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            StorageError::Migration("Failed to run migrations".to_string())
        })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PostgresUser> for User {
    fn from(user: PostgresUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at)
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
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[async_trait]
impl UserStorage for PostgresStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            INSERT INTO users (id, email) 
            VALUES ($1, $2) 
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_str())
        .bind(&user.email)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            StorageError::Database("Failed to create user".to_string())
        })?;

        Ok(user.into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id = $1
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user");
            StorageError::Database("Failed to get user".to_string())
        })?;

        match user {
            Some(user) => Ok(Some(user.into())),
            None => Ok(None),
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by email");
            StorageError::Database("Failed to get user by email".to_string())
        })?;

        match user {
            Some(user) => Ok(Some(user.into())),
            None => Ok(None),
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
                StorageError::Database("Failed to get or create user by email".to_string())
            })?;

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            UPDATE users 
            SET email = $1, name = $2, email_verified_at = $3, updated_at = $4 
            WHERE id = $5
            RETURNING id, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.email_verified_at)
        .bind(user.updated_at)
        .bind(user.id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            StorageError::Database("Failed to update user".to_string())
        })?;

        Ok(user.into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                StorageError::Database("Failed to delete user".to_string())
            })?;

        Ok(())
    }

    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to set user email verified");
                StorageError::Database("Failed to set user email verified".to_string())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use sqlx::types::chrono::Utc;
    use std::time::Duration;
    use torii_core::session::SessionToken;
    use torii_core::{Session, SessionStorage};

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
        storage
            .create_user(
                &NewUser::builder()
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
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
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
