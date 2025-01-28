use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use torii_core::migration::PluginMigration;
use torii_core::Error;

// Example implementation for EmailPasswordPlugin
pub(crate) struct AddPasswordColumn;

#[async_trait]
impl PluginMigration for AddPasswordColumn {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "add_password_column"
    }

    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            r#"
            ALTER TABLE torii_users ADD COLUMN password_hash TEXT NOT NULL;
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query("ALTER TABLE torii_users DROP COLUMN password_hash;")
            .execute(pool)
            .await?;
        Ok(())
    }
}
