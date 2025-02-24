use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Database, Sqlite, SqlitePool};
use torii_migration::{Migration, MigrationError, MigrationManager, MigrationRecord};

pub struct SqliteMigrationManager {
    pool: SqlitePool,
}

impl SqliteMigrationManager {
    #[allow(dead_code)]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MigrationManager<Sqlite> for SqliteMigrationManager {
    async fn initialize(&self) -> Result<(), MigrationError> {
        sqlx::query(
            format!(
                r#"
            CREATE TABLE IF NOT EXISTS {} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL DEFAULT (unixepoch())
            );"#,
                self.get_migration_table_name()
            )
            .as_str(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn up(&self, migrations: &[Box<dyn Migration<Sqlite>>]) -> Result<(), MigrationError> {
        for migration in migrations {
            if !self.is_applied(migration.version()).await? {
                let mut tx = self.pool.begin().await?;

                tracing::info!(
                    "Applying migration {} ({})",
                    migration.name(),
                    migration.version()
                );

                migration
                    .up(&mut *tx as &mut <Sqlite as Database>::Connection)
                    .await?;

                sqlx::query(
                    format!(
                        "INSERT INTO {} (version, name, applied_at) VALUES (?, ?, ?)",
                        self.get_migration_table_name()
                    )
                    .as_str(),
                )
                .bind(migration.version())
                .bind(migration.name())
                .bind(Utc::now().timestamp())
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
            }
        }
        Ok(())
    }

    async fn down(&self, migrations: &[Box<dyn Migration<Sqlite>>]) -> Result<(), MigrationError> {
        for migration in migrations {
            if self.is_applied(migration.version()).await? {
                let mut tx = self.pool.begin().await?;

                tracing::info!(
                    "Rolling back migration {} ({})",
                    migration.name(),
                    migration.version()
                );

                migration
                    .down(&mut *tx as &mut <Sqlite as Database>::Connection)
                    .await?;

                sqlx::query(
                    format!(
                        "DELETE FROM {} WHERE version = ?",
                        self.get_migration_table_name()
                    )
                    .as_str(),
                )
                .bind(migration.version())
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
            }
        }
        Ok(())
    }

    async fn get_applied_migrations(&self) -> Result<Vec<MigrationRecord>, MigrationError> {
        let records = sqlx::query_as::<_, MigrationRecord>(
            format!(
                "SELECT version, name, applied_at FROM {}",
                self.get_migration_table_name()
            )
            .as_str(),
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(records)
    }

    async fn is_applied(&self, version: i64) -> Result<bool, MigrationError> {
        let result: bool = sqlx::query_scalar(
            format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE version = ?)",
                self.get_migration_table_name()
            )
            .as_str(),
        )
        .bind(version)
        .fetch_one(&self.pool)
        .await?;
        Ok(result)
    }
}

pub struct CreateUsersTable;

#[async_trait]
impl Migration<Sqlite> for CreateUsersTable {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "CreateUsersTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT,
                email TEXT NOT NULL,
                email_verified_at INTEGER,
                password_hash TEXT,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch()),
                UNIQUE(email),
                UNIQUE(id)
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS users")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreateSessionsTable;

#[async_trait]
impl Migration<Sqlite> for CreateSessionsTable {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "CreateSessionsTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_agent TEXT,
                ip_address TEXT,
                expires_at INTEGER NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch()),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS sessions")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreateOAuthAccountsTable;

#[async_trait]
impl Migration<Sqlite> for CreateOAuthAccountsTable {
    fn version(&self) -> i64 {
        3
    }

    fn name(&self) -> &str {
        "CreateOAuthAccountsTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                id INTEGER PRIMARY KEY,
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch()),
                FOREIGN KEY(user_id) REFERENCES users(id),
                UNIQUE(user_id, provider, subject)
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS oauth_accounts")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreatePasskeysTable;

#[async_trait]
impl Migration<Sqlite> for CreatePasskeysTable {
    fn version(&self) -> i64 {
        4
    }

    fn name(&self) -> &str {
        "CreatePasskeysTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passkeys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch()),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS passkeys")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreatePasskeyChallengesTable;

#[async_trait]
impl Migration<Sqlite> for CreatePasskeyChallengesTable {
    fn version(&self) -> i64 {
        5
    }

    fn name(&self) -> &str {
        "CreatePasskeyChallengesTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passkey_challenges (
                id TEXT PRIMARY KEY,
                challenge TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch())
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS passkey_challenges")
            .execute(conn)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    fn setup_test() {
        let _ = tracing_subscriber::fmt().try_init();
    }

    #[tokio::test]
    async fn test_migrations() -> Result<(), MigrationError> {
        setup_test();

        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");
        let manager = SqliteMigrationManager::new(pool);

        // Initialize migrations table
        manager.initialize().await?;

        // Test up migrations
        let migrations: Vec<Box<dyn Migration<Sqlite>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
        ];
        manager.up(&migrations).await?;

        // Verify migration was applied
        let applied = manager.is_applied(5).await?;
        assert!(applied, "Migration should be applied");

        // Test down migrations
        manager.down(&migrations).await?;

        // Verify migration was rolled back
        let applied = manager.is_applied(5).await?;
        assert!(!applied, "Migration should be rolled back");

        Ok(())
    }

    #[tokio::test]
    async fn test_up_down_up() -> Result<(), MigrationError> {
        setup_test();

        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");
        let manager = SqliteMigrationManager::new(pool);

        // Initialize migrations table
        manager.initialize().await?;

        // Test up migrations
        let migrations: Vec<Box<dyn Migration<Sqlite>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
        ];
        manager.up(&migrations).await?;

        // Test down migrations
        manager.down(&migrations).await?;

        // Test up migrations again
        manager.up(&migrations).await?;

        // Verify migration was applied
        let applied = manager.is_applied(5).await?;
        assert!(applied, "Migration should be applied");

        Ok(())
    }
}
