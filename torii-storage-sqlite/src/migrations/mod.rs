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
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS oauth_state (
                csrf_state TEXT PRIMARY KEY,
                pkce_verifier TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch())
            );"#,
        )
        .execute(&mut *conn)
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

pub struct CreateIndexes;

#[async_trait]
impl Migration<Sqlite> for CreateIndexes {
    fn version(&self) -> i64 {
        6
    }

    fn name(&self) -> &str {
        "CreateIndexes"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        // Create all indexes
        sqlx::query(
            r#"
            -- Users table indexes
            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

            -- Sessions table indexes
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

            -- OAuth accounts table indexes
            CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id);
            CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_subject ON oauth_accounts(provider, subject);

            -- OAuth state table indexes
            CREATE INDEX IF NOT EXISTS idx_oauth_state_expires_at ON oauth_state(expires_at);

            -- Passkeys table indexes
            CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id);

            -- Passkey challenges table indexes
            CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at ON passkey_challenges(expires_at);
            "#,
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        // Drop all indexes in a single query
        sqlx::query(
            r#"
            DROP INDEX IF EXISTS idx_users_email;
            DROP INDEX IF EXISTS idx_sessions_user_id;
            DROP INDEX IF EXISTS idx_sessions_expires_at;
            DROP INDEX IF EXISTS idx_oauth_accounts_user_id;
            DROP INDEX IF EXISTS idx_oauth_accounts_provider_subject;
            DROP INDEX IF EXISTS idx_oauth_state_expires_at;
            DROP INDEX IF EXISTS idx_passkeys_user_id;
            DROP INDEX IF EXISTS idx_passkey_challenges_expires_at;
            "#,
        )
        .execute(conn)
        .await?;

        Ok(())
    }
}

pub struct CreateMagicLinksTable;

#[async_trait::async_trait]
impl Migration<Sqlite> for CreateMagicLinksTable {
    fn version(&self) -> i64 {
        7
    }

    fn name(&self) -> &str {
        "CreateMagicLinksTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS magic_links (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                used_at INTEGER,
                expires_at INTEGER NOT NULL,
                created_at INTEGER DEFAULT (unixepoch()),
                updated_at INTEGER DEFAULT (unixepoch()),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(token)
            );

            -- Magic links table indexes
            CREATE INDEX IF NOT EXISTS idx_magic_links_used_at ON magic_links(used_at);
            CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at ON magic_links(expires_at);
            CREATE INDEX IF NOT EXISTS idx_magic_links_user_id ON magic_links(user_id);
            CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token);
            "#,
        )
        .execute(conn)
        .await?;

        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Sqlite as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            DROP TABLE IF EXISTS magic_links;
            DROP INDEX IF EXISTS idx_magic_links_used_at;
            DROP INDEX IF EXISTS idx_magic_links_expires_at;
            DROP INDEX IF EXISTS idx_magic_links_user_id;
            DROP INDEX IF EXISTS idx_magic_links_token;
            "#,
        )
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
            Box::new(CreateIndexes),
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await?;

        // Verify migration was applied
        let applied = manager.is_applied(7).await?;
        assert!(applied, "Migration should be applied");

        // Test down migrations
        manager.down(&migrations).await?;

        // Verify migration was rolled back
        let applied = manager.is_applied(7).await?;
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
            Box::new(CreateIndexes),
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await?;

        // Test down migrations
        manager.down(&migrations).await?;

        // Test up migrations again
        manager.up(&migrations).await?;

        // Verify migration was applied
        let applied = manager.is_applied(7).await?;
        assert!(applied, "Migration should be applied");

        Ok(())
    }
}
