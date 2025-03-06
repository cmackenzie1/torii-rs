mod entities;
mod migrations;
mod password;
mod session;
mod user;

use sea_orm::DatabaseConnection;
use sea_orm_migration::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum SeaORMStorageError {
    #[error(transparent)]
    Database(#[from] sea_orm::DbErr),
    #[error("User not found")]
    UserNotFound,
}

pub struct SeaORMStorage {
    pool: DatabaseConnection,
}

impl SeaORMStorage {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
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
