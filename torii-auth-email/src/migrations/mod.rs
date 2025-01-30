use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use torii_core::migration::PluginMigration;
use torii_core::Error;

/// Add a password hash column to the users table.
pub(crate) struct AddPasswordHashColumn;

#[async_trait]
impl PluginMigration for AddPasswordHashColumn {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "add_password_hash_column"
    }

    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            r#"
            ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL;
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query("ALTER TABLE users DROP COLUMN password_hash;")
            .execute(pool)
            .await?;
        Ok(())
    }
}
