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

#[cfg(test)]
mod tests {
    use super::*;

    use sqlx::SqlitePool;

    #[tokio::test]
    async fn test_migration_up_down_up() -> Result<(), Error> {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test pool");

        // Create users table first since we're adding a column to it
        sqlx::query(
            r#"
            CREATE TABLE users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                email_verified_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&pool)
        .await
        .expect("Failed to create users table");

        let migration = AddPasswordHashColumn;

        // First up migration
        migration.up(&pool).await?;

        // Verify column exists
        let has_column = sqlx::query(
            r#"
            SELECT 1 FROM pragma_table_info('users')
            WHERE name = 'password_hash'
            "#,
        )
        .fetch_optional(&pool)
        .await?;
        assert!(
            has_column.is_some(),
            "Column should exist after up migration"
        );

        // Down migration
        migration.down(&pool).await?;

        // Verify column was removed
        let has_column = sqlx::query(
            r#"
            SELECT 1 FROM pragma_table_info('users')
            WHERE name = 'password_hash'
            "#,
        )
        .fetch_optional(&pool)
        .await?;
        assert!(
            has_column.is_none(),
            "Column should not exist after down migration"
        );

        // Second up migration
        migration.up(&pool).await?;

        // Verify column exists again
        let has_column = sqlx::query(
            r#"
            SELECT 1 FROM pragma_table_info('users')
            WHERE name = 'password_hash'
            "#,
        )
        .fetch_optional(&pool)
        .await?;
        assert!(
            has_column.is_some(),
            "Column should exist after second up migration"
        );

        Ok(())
    }
}
