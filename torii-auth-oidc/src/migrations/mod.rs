use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use torii_core::migration::PluginMigration;
use torii_core::Error;

pub(crate) struct CreateOidcTables;

#[async_trait]
impl PluginMigration for CreateOidcTables {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "create_oidc_tables"
    }

    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS oidc_accounts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
                )
                "#,
        )
        .execute(pool)
        .await?;

        Ok(())
    }

    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(r#"DROP TABLE IF EXISTS oidc_accounts"#)
            .execute(pool)
            .await?;

        Ok(())
    }
}
