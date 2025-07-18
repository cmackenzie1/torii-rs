//! SeaORM storage backend for Torii
//!
//! This crate provides a SeaORM-based storage implementation for the Torii authentication framework.
//! SeaORM is a modern async ORM for Rust that provides type-safe database operations and supports
//! multiple database backends including PostgreSQL, MySQL, and SQLite.
//!
//! # Features
//!
//! - **Multi-Database Support**: Works with PostgreSQL, MySQL, and SQLite through SeaORM
//! - **Type-Safe Operations**: Leverages SeaORM's compile-time query validation
//! - **Async/Await**: Fully async database operations with tokio
//! - **Automatic Migrations**: Built-in schema migration management
//! - **User Management**: Store and retrieve user accounts with email verification support
//! - **Session Management**: Handle user sessions with configurable expiration
//! - **Password Authentication**: Secure password hashing and verification
//! - **OAuth Integration**: Store OAuth account connections and tokens
//! - **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_storage_seaorm::SeaORMStorage;
//! use torii_core::UserId;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to database (supports PostgreSQL, MySQL, SQLite)
//!     let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await?;
//!     
//!     // Run migrations to set up the schema
//!     storage.migrate().await?;
//!     
//!     // Convert to repository provider and use with Torii
//!     let repositories = std::sync::Arc::new(storage.into_repository_provider());
//!     let torii = torii::Torii::new(repositories);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Repository Provider
//!
//! The crate provides [`SeaORMRepositoryProvider`] which implements the [`RepositoryProvider`] trait
//! from `torii-core`, allowing it to be used directly with the main Torii authentication coordinator.
//!
//! # Database Support
//!
//! This crate can be used with any database backend supported by SeaORM:
//! - **PostgreSQL**: Production-ready with full feature support
//! - **MySQL**: Production-ready with full feature support  
//! - **SQLite**: Great for development and smaller deployments
//!
//! # Storage Implementations
//!
//! This crate implements repository patterns for:
//! - User account management and profile storage
//! - Session management with automatic expiration
//! - Password credential storage with secure hashing
//! - OAuth account connections and token management
//! - WebAuthn passkey credentials and challenge handling
//!
//! # Entity Models
//!
//! The crate defines SeaORM entity models for all authentication data:
//! - `User` - User accounts and profile information
//! - `Session` - Active user sessions
//! - `Password` - Hashed password credentials  
//! - `OAuthAccount` - Connected OAuth accounts
//! - `Passkey` - WebAuthn passkey credentials
//! - `PasskeyChallenge` - Temporary passkey challenges
//!
//! All entities include appropriate relationships and indexes for optimal performance.

mod entities;
mod migrations;
mod oauth;
mod passkey;
mod password;
mod session;
mod token;
mod user;

pub mod repositories;
pub use repositories::SeaORMRepositoryProvider;

use migrations::Migrator;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum SeaORMStorageError {
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error("User not found")]
    UserNotFound,
}

/// SeaORM storage backend
///
/// This storage backend uses SeaORM to manage database connections and migrations.
/// It provides a `connect` method to create a new storage instance from a database URL.
/// It also provides a `migrate` method to apply pending migrations.
///
/// # Example
///
/// ```rust,no_run
/// use torii_storage_seaorm::SeaORMStorage;
///
/// #[tokio::main]
/// async fn main() {
///     let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await.unwrap();
///     let _ = storage.migrate().await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct SeaORMStorage {
    pool: DatabaseConnection,
}

impl SeaORMStorage {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }

    pub async fn connect(url: &str) -> Result<Self, SeaORMStorageError> {
        let pool = Database::connect(url).await?;
        pool.ping().await?;

        Ok(Self::new(pool))
    }

    pub async fn migrate(&self) -> Result<(), SeaORMStorageError> {
        Migrator::up(&self.pool, None).await.unwrap();

        Ok(())
    }

    /// Create a repository provider from this storage instance
    pub fn into_repository_provider(self) -> SeaORMRepositoryProvider {
        SeaORMRepositoryProvider::new(self.pool)
    }
}
#[cfg(test)]
mod tests {
    use sea_orm::Database;

    use crate::migrations::Migrator;

    use super::*;

    #[tokio::test]
    async fn test_migrations_up() {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        let migrations = Migrator::get_pending_migrations(&pool).await.unwrap();
        migrations.iter().for_each(|m| {
            println!("{}: {}", m.name(), m.status());
        });
        Migrator::up(&pool, None).await.unwrap();
        let migrations = Migrator::get_pending_migrations(&pool).await.unwrap();
        migrations.iter().for_each(|m| {
            println!("{}: {}", m.name(), m.status());
        });
    }
}
