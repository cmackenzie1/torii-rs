use crate::error::Error;
use async_trait::async_trait;
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;

#[derive(Debug)]
pub struct Migration {
    pub version: i64,
    pub name: String,
    pub description: String,
    pub sql: String,
}

#[async_trait]
pub trait PluginMigration: Send + Sync {
    fn version(&self) -> i64;
    fn name(&self) -> &str;
    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;
    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;
}
