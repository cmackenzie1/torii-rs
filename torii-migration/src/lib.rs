use async_trait::async_trait;
use sqlx::Database;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("Migration failed: {0}")]
    Migration(String),
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub type Result<T> = std::result::Result<T, MigrationError>;

#[async_trait]
pub trait Migration<DB: Database>: Send + Sync {
    /// Execute the migration
    async fn up<'a>(&'a self, conn: &'a mut <DB as Database>::Connection) -> Result<()>;

    /// Rollback the migration
    async fn down<'a>(&'a self, conn: &'a mut <DB as Database>::Connection) -> Result<()>;

    /// Unique version number for ordering migrations
    fn version(&self) -> i64;

    /// Human readable name of the migration
    fn name(&self) -> &str;
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MigrationRecord {
    pub version: i64,
    pub name: String,
    pub applied_at: i64, // unix timestamp since no database can agree on a datetime type
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
