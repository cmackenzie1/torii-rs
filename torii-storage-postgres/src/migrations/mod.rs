use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Database, PgPool, Postgres};
use torii_migration::{Migration, MigrationError, MigrationManager, MigrationRecord};

pub struct PostgresMigrationManager {
    pool: PgPool,
}

impl PostgresMigrationManager {
    #[allow(dead_code)]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MigrationManager<Postgres> for PostgresMigrationManager {
    async fn initialize(&self) -> Result<(), MigrationError> {
        sqlx::query(
            format!(
                r#"
            CREATE TABLE IF NOT EXISTS {} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );"#,
                self.get_migration_table_name()
            )
            .as_str(),
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn up(&self, migrations: &[Box<dyn Migration<Postgres>>]) -> Result<(), MigrationError> {
        for migration in migrations {
            if !self.is_applied(migration.version()).await? {
                let mut tx = self.pool.begin().await?;

                tracing::info!(
                    "Applying migration {} ({})",
                    migration.name(),
                    migration.version()
                );

                migration
                    .up(&mut *tx as &mut <Postgres as Database>::Connection)
                    .await?;

                sqlx::query(
                    format!(
                        "INSERT INTO {} (version, name, applied_at) VALUES ($1, $2, $3)",
                        self.get_migration_table_name()
                    )
                    .as_str(),
                )
                .bind(migration.version())
                .bind(migration.name())
                .bind(Utc::now())
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
            }
        }
        Ok(())
    }

    async fn down(
        &self,
        migrations: &[Box<dyn Migration<Postgres>>],
    ) -> Result<(), MigrationError> {
        for migration in migrations {
            if self.is_applied(migration.version()).await? {
                let mut tx = self.pool.begin().await?;

                tracing::info!(
                    "Rolling back migration {} ({})",
                    migration.name(),
                    migration.version()
                );

                migration
                    .down(&mut *tx as &mut <Postgres as Database>::Connection)
                    .await?;

                sqlx::query(
                    format!(
                        "DELETE FROM {} WHERE version = $1",
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
                "SELECT EXISTS(SELECT 1 FROM {} WHERE version = $1)",
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
impl Migration<Postgres> for CreateUsersTable {
    fn version(&self) -> i64 {
        1
    }

    fn name(&self) -> &str {
        "CreateUsersTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(r#"CREATE EXTENSION IF NOT EXISTS "pgcrypto""#)
            .execute(&mut *conn)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                name TEXT,
                email TEXT NOT NULL,
                email_verified_at TIMESTAMPTZ,
                password_hash TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(email),
                UNIQUE(id)
            )"#,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS users CASCADE")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreateSessionsTable;

#[async_trait]
impl Migration<Postgres> for CreateSessionsTable {
    fn version(&self) -> i64 {
        2
    }

    fn name(&self) -> &str {
        "CreateSessionsTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS sessions (
                id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                user_id TEXT NOT NULL,
                user_agent TEXT,
                ip_address TEXT,
                token TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );"#,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS sessions CASCADE")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

pub struct CreateOAuthAccountsTable;

#[async_trait]
impl Migration<Postgres> for CreateOAuthAccountsTable {
    fn version(&self) -> i64 {
        3
    }

    fn name(&self) -> &str {
        "CreateOAuthAccountsTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS oauth_accounts (
                id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                user_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, provider, subject)
            );"#,
        )
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS oauth_accounts CASCADE")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

pub struct CreatePasskeysTable;

#[async_trait]
impl Migration<Postgres> for CreatePasskeysTable {
    fn version(&self) -> i64 {
        4
    }

    fn name(&self) -> &str {
        "CreatePasskeysTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passkeys (
                id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                credential_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS passkeys")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreatePasskeyChallengesTable;

#[async_trait]
impl Migration<Postgres> for CreatePasskeyChallengesTable {
    fn version(&self) -> i64 {
        5
    }

    fn name(&self) -> &str {
        "CreatePasskeyChallengesTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS passkey_challenges (
                id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                challenge_id TEXT NOT NULL,
                challenge TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(challenge_id)
            );"#,
        )
        .execute(conn)
        .await?;
        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP TABLE IF EXISTS passkey_challenges")
            .execute(conn)
            .await?;
        Ok(())
    }
}

pub struct CreateIndexes;

#[async_trait]
impl Migration<Postgres> for CreateIndexes {
    fn version(&self) -> i64 {
        6
    }

    fn name(&self) -> &str {
        "CreateIndexes"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        // Index for email searches
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            .execute(&mut *conn)
            .await?;

        // Index for sessions user_id foreign key
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            .execute(&mut *conn)
            .await?;

        // Index for sessions expiration
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            .execute(&mut *conn)
            .await?;

        // Indexes for oauth_accounts lookups
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id)",
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_subject ON oauth_accounts(provider, subject)",
        )
        .execute(&mut *conn)
        .await?;

        // Index for passkeys user_id
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_passkeys_user_id ON passkeys(user_id)")
            .execute(&mut *conn)
            .await?;

        // Index for passkey credential lookup
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id)",
        )
        .execute(&mut *conn)
        .await?;

        // Index for passkey challenges expiration
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_passkey_challenges_expires_at ON passkey_challenges(expires_at)",
        )
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP INDEX IF EXISTS idx_users_email")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_sessions_user_id")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_sessions_expires_at")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_oauth_accounts_user_id")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_oauth_accounts_provider_subject")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_passkeys_user_id")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_passkeys_credential_id")
            .execute(&mut *conn)
            .await?;
        sqlx::query("DROP INDEX IF EXISTS idx_passkey_challenges_expires_at")
            .execute(&mut *conn)
            .await?;
        Ok(())
    }
}

pub struct CreateMagicLinksTable;

#[async_trait::async_trait]
impl Migration<Postgres> for CreateMagicLinksTable {
    fn version(&self) -> i64 {
        7
    }

    fn name(&self) -> &str {
        "CreateMagicLinksTable"
    }

    async fn up<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS magic_links (
                id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                used_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(token)
            )"#,
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_magic_links_used_at ON magic_links(used_at)")
            .execute(&mut *conn)
            .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_magic_links_expires_at ON magic_links(expires_at)",
        )
        .execute(&mut *conn)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_magic_links_user_id ON magic_links(user_id)")
            .execute(&mut *conn)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_magic_links_token ON magic_links(token)")
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    async fn down<'a>(
        &'a self,
        conn: &'a mut <Postgres as Database>::Connection,
    ) -> Result<(), MigrationError> {
        sqlx::query("DROP INDEX IF EXISTS idx_magic_links_expires_at")
            .execute(&mut *conn)
            .await?;

        sqlx::query("DROP INDEX IF EXISTS idx_magic_links_user_id")
            .execute(&mut *conn)
            .await?;

        sqlx::query("DROP INDEX IF EXISTS idx_magic_links_token")
            .execute(&mut *conn)
            .await?;

        sqlx::query("DROP TABLE IF EXISTS magic_links")
            .execute(&mut *conn)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use sqlx::PgPool;

    pub(crate) async fn setup_test() -> Result<PostgresMigrationManager, sqlx::Error> {
        // TODO: this function is leaking postgres databases after the test is done.
        // We should find a way to clean up the database after the test is done.

        let _ = tracing_subscriber::fmt().try_init();

        let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/postgres")
            .await
            .expect("Failed to create pool");

        let db_name = format!("torii_test_{}", rand::rng().random_range(1..i64::MAX));

        // Drop the database if it exists
        sqlx::query(format!("DROP DATABASE IF EXISTS {db_name}").as_str())
            .execute(&pool)
            .await
            .expect("Failed to drop database");

        // Create a new database for the test
        sqlx::query(format!("CREATE DATABASE {db_name}").as_str())
            .execute(&pool)
            .await
            .expect("Failed to create database");

        let pool = PgPool::connect(
            format!("postgres://postgres:postgres@localhost:5432/{db_name}").as_str(),
        )
        .await
        .expect("Failed to create pool");

        // Initialize migrations table
        let manager = PostgresMigrationManager::new(pool);
        manager
            .initialize()
            .await
            .expect("Failed to initialize migrations");

        Ok(manager)
    }

    #[tokio::test]
    async fn test_migrations() -> Result<(), MigrationError> {
        let manager = setup_test().await.map_err(MigrationError::Sqlx)?;

        // Test up migrations
        let migrations: Vec<Box<dyn Migration<Postgres>>> = vec![
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
        let manager = setup_test().await.map_err(MigrationError::Sqlx)?;

        // Test up migrations
        let migrations: Vec<Box<dyn Migration<Postgres>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
            Box::new(CreateIndexes),
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await?;

        Ok(())
    }
}
