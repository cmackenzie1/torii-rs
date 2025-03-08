mod entities;
mod magic_link;
mod migrations;
mod oauth;
mod passkey;
mod password;
mod session;
mod user;

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
/// ```rust
/// use torii_storage_seaorm::SeaORMStorage;
/// let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await.unwrap();
/// let _ = storage.migrate().await.unwrap();
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
        let _ = Migrator::up(&pool, None).await.unwrap();
        let migrations = Migrator::get_pending_migrations(&pool).await.unwrap();
        migrations.iter().for_each(|m| {
            println!("{}: {}", m.name(), m.status());
        });
    }
}
