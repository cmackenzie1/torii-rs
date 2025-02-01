use async_trait::async_trait;
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;

use crate::error::Error;
use crate::migration::PluginMigration;
pub struct CreateUsersTable;

#[async_trait]
impl PluginMigration for CreateUsersTable {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "create_users_table"
    }

    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT,
                email TEXT,
                email_verified_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(email),
                UNIQUE(id)
            )",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query("DROP TABLE users").execute(pool).await?;

        Ok(())
    }
}

pub struct CreateSessionsTable;

#[async_trait]
impl PluginMigration for CreateSessionsTable {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "create_sessions_table"
    }

    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                token TEXT,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )",
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query("DROP TABLE sessions").execute(pool).await?;

        Ok(())
    }
}
