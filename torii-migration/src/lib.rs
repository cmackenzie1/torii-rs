//! Migration management for SQL databases in Torii
//!
//! This module provides traits and utilities for managing SQL database migrations in Torii.
//! It defines a common interface for writing migrations that can be used across different
//! SQL database backends.
//!
//! The main traits are:
//! - [`Migration`]: Defines a single SQL migration with up/down operations
//! - [`MigrationManager`]: Manages the execution and tracking of migrations
//!
//! Migrations are tracked in a database table (default name: `_torii_migrations`) to record
//! which migrations have been applied and when.
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::Database;
use thiserror::Error;
use torii_core::{Error, error::StorageError};

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}

impl From<MigrationError> for Error {
    fn from(value: MigrationError) -> Self {
        match value {
            MigrationError::Sqlx(e) => Error::Storage(StorageError::Database(e.to_string())),
        }
    }
}

pub type Result<T> = std::result::Result<T, MigrationError>;

#[async_trait]
pub trait Migration<DB: Database>: Send + Sync {
    /// Unique version number for ordering migrations
    fn version(&self) -> i64;

    /// Human readable name of the migration
    fn name(&self) -> &str;

    /// Execute the migration
    async fn up<'a>(&'a self, conn: &'a mut <DB as Database>::Connection) -> Result<()>;

    /// Rollback the migration
    async fn down<'a>(&'a self, conn: &'a mut <DB as Database>::Connection) -> Result<()>;
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MigrationRecord {
    pub version: i64,
    pub name: String,
    pub applied_at: DateTime<Utc>,
}

#[async_trait]
pub trait MigrationManager<DB: Database>: Send + Sync {
    fn get_migration_table_name(&self) -> &str {
        "_torii_migrations"
    }

    /// Initialize migration tracking table
    async fn initialize(&self) -> Result<()>;

    /// Apply pending migrations
    async fn up(&self, migrations: &[Box<dyn Migration<DB>>]) -> Result<()>;

    /// Rollback migrations
    async fn down(&self, migrations: &[Box<dyn Migration<DB>>]) -> Result<()>;

    /// Get list of applied migrations
    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>>;

    /// Check if specific migration was applied
    async fn is_applied(&self, version: i64) -> Result<bool>;
}
