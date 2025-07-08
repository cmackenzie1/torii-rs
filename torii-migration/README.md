# torii-migration

Database migration management for the Torii authentication framework.

This crate provides traits and utilities for managing SQL database migrations in Torii. It defines a common interface for writing migrations that can be used across different SQL database backends like SQLite, PostgreSQL, and MySQL.

## Features

- **Generic Migration Interface**: Common traits for all database backends
- **Migration Tracking**: Automatic tracking of applied migrations
- **Async/Await Support**: Fully async migration operations
- **Database Agnostic**: Works with any sqlx-supported database
- **Rollback Support**: Bidirectional migrations with up/down operations
- **Timestamp Tracking**: Records when migrations were applied

## Usage

This crate is primarily used internally by Torii storage backends, but can be used directly if you need custom migration management.

Add this to your `Cargo.toml`:

```toml
[dependencies]
torii-migration = "0.4.0"
```

### Basic Migration

```rust
use torii_migration::{Migration, MigrationManager};
use async_trait::async_trait;
use sqlx::Sqlite;

struct CreateUsersTable;

#[async_trait]
impl Migration<Sqlite> for CreateUsersTable {
    fn version(&self) -> i64 {
        20250101_000001
    }

    fn name(&self) -> &str {
        "create_users_table"
    }

    async fn up<'a>(&'a self, conn: &'a mut sqlx::SqliteConnection) -> torii_migration::Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                email_verified_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            "#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(&'a self, conn: &'a mut sqlx::SqliteConnection) -> torii_migration::Result<()> {
        sqlx::query("DROP TABLE users").execute(conn).await?;
        Ok(())
    }
}
```

### Migration Manager

```rust
use torii_migration::{Migration, MigrationManager};
use sqlx::SqlitePool;

// Implement MigrationManager for your specific database
struct SqliteMigrationManager {
    pool: SqlitePool,
}

impl SqliteMigrationManager {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MigrationManager<sqlx::Sqlite> for SqliteMigrationManager {
    // Implementation details...
}
```

## Core Traits

### Migration

The `Migration` trait defines a single database migration:

```rust
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
```

### MigrationManager

The `MigrationManager` trait manages the execution and tracking of migrations:

```rust
#[async_trait]
pub trait MigrationManager<DB: Database>: Send + Sync {
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
```

## Migration Tracking

Migrations are tracked in a database table (default name: `_torii_migrations`) that records:

- **version**: The migration version number
- **name**: Human-readable migration name
- **applied_at**: Timestamp when the migration was applied

## Version Numbering

It's recommended to use timestamp-based version numbers for migrations:

```rust
// Format: YYYYMMDD_HHMMSS
20250101_000001  // 2025-01-01 00:00:01
20250101_120000  // 2025-01-01 12:00:00
```

This ensures migrations are applied in the correct order and prevents conflicts.

## Database Support

This crate works with any database supported by sqlx:

- **SQLite**: Great for development and smaller deployments
- **PostgreSQL**: Production-ready with full feature support
- **MySQL**: Production-ready with full feature support

## Error Handling

The crate provides comprehensive error handling with the `MigrationError` type that integrates with Torii's error system:

```rust
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),
}
```

## Integration with Storage Backends

Storage backends like `torii-storage-sqlite` and `torii-storage-postgres` use this crate to provide automatic schema management. Users typically don't need to interact with this crate directly unless they're implementing custom storage backends.