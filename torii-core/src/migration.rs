use crate::error::Error;
use async_trait::async_trait;
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;

#[derive(Debug)]
/// Represents a database migration with version, name, description and SQL.
///
/// # Example
/// ```
/// use torii_core::Migration;
///
/// let migration = Migration {
///     version: 1,
///     name: String::from("create_users"),
///     description: String::from("Creates the users table"),
///     sql: String::from("CREATE TABLE users (id INTEGER PRIMARY KEY)"),
/// };
/// ```
pub struct Migration {
    pub version: i64,
    pub name: String,
    pub description: String,
    pub sql: String,
}

#[async_trait]
/// Represents a database migration with version, name, description and SQL.
///
/// All migrations should provide an up and down migration.
///
/// # Example
/// ```
/// use torii_core::Migration;
///
pub trait PluginMigration: Send + Sync {
    fn version(&self) -> i64;
    fn name(&self) -> &str;
    async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;
    async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    struct TestMigration {
        version: i64,
        name: String,
    }

    #[async_trait]
    impl PluginMigration for TestMigration {
        fn version(&self) -> i64 {
            self.version
        }

        fn name(&self) -> &str {
            &self.name
        }

        async fn up(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
            sqlx::query("CREATE TABLE test (id INTEGER PRIMARY KEY)")
                .execute(pool)
                .await?;
            Ok(())
        }

        async fn down(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
            sqlx::query("DROP TABLE test").execute(pool).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_migration_up_down() -> Result<(), Error> {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create test db");

        let migration = TestMigration {
            version: 1,
            name: "test_migration".to_string(),
        };

        // Test up migration
        migration.up(&pool).await?;

        // Verify table exists
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='test'")
                .fetch_optional(&pool)
                .await?;
        assert!(result.is_some(), "Table should exist after up migration");

        // Test down migration
        migration.down(&pool).await?;

        // Verify table was dropped
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='test'")
                .fetch_optional(&pool)
                .await?;
        assert!(
            result.is_none(),
            "Table should not exist after down migration"
        );

        Ok(())
    }

    #[test]
    fn test_migration_metadata() {
        let migration = TestMigration {
            version: 42,
            name: "test_migration".to_string(),
        };

        assert_eq!(migration.version(), 42);
        assert_eq!(migration.name(), "test_migration");
    }
}
