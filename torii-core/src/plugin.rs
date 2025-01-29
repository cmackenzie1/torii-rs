use async_trait::async_trait;
use sqlx::{Pool, Row, Sqlite};
use std::collections::HashMap;

use crate::error::Error;
use crate::migration::PluginMigration;

/// Represents a user in the database. All plugins must return a user when
/// authenticating a user.
#[derive(Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
}

/// Represents the credentials used to authenticate a user.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Email and password credentials.
    EmailPassword { email: String, password: String },
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CreateUserParams {
    /// Create a user with an email and password.
    EmailPassword { email: String, password: String },
}

#[async_trait]
pub trait AuthPlugin: Send + Sync {
    fn name(&self) -> &'static str;
    async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;
    async fn authenticate(&self, pool: &Pool<Sqlite>, creds: &Credentials) -> Result<User, Error>;
    async fn create_user(
        &self,
        pool: &Pool<Sqlite>,
        params: &CreateUserParams,
    ) -> Result<(), Error>;
    fn migrations(&self) -> Vec<Box<dyn PluginMigration>>;
}

/// Manages a collection of authentication plugins.
pub struct PluginManager {
    plugins: HashMap<String, Box<dyn AuthPlugin>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    /// Register a new authentication plugin.
    pub fn register(&mut self, plugin: Box<dyn AuthPlugin>) {
        self.plugins.insert(plugin.name().to_string(), plugin);
    }

    /// Setup all registered plugins. This should be called before any authentication
    /// is attempted.
    pub async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        for plugin in self.plugins.values() {
            plugin.setup(pool).await?;
        }
        Ok(())
    }

    /// Authenticate a user using a specific method by name.
    ///
    /// This will return an error if the method is not registered.
    pub async fn authenticate(
        &self,
        method: &str,
        pool: &Pool<Sqlite>,
        creds: &Credentials,
    ) -> Result<User, Error> {
        let plugin = self
            .plugins
            .get(method)
            .ok_or_else(|| Error::Auth("Unknown auth method".into()))?;

        plugin.authenticate(pool, creds).await
    }
}

impl PluginManager {
    async fn init_migration_table(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS torii_migrations (
                id INTEGER PRIMARY KEY,
                plugin_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                name TEXT NOT NULL,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(plugin_name, version)
            )
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn init_user_table(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS torii_users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(username)
            )
            "#,
        )
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn get_applied_migrations(
        &self,
        pool: &Pool<Sqlite>,
        plugin_name: &str,
    ) -> Result<Vec<i64>, Error> {
        let rows = sqlx::query(
            "SELECT version FROM torii_migrations WHERE plugin_name = ? ORDER BY version",
        )
        .bind(plugin_name)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    async fn apply_migration(
        &self,
        pool: &Pool<Sqlite>,
        plugin_name: &str,
        migration: &dyn PluginMigration,
    ) -> Result<(), Error> {
        // Start transaction
        let mut tx = pool.begin().await?;

        // Apply migration
        migration.up(pool).await?;

        // Record migration
        sqlx::query("INSERT INTO torii_migrations (plugin_name, version, name) VALUES (?, ?, ?)")
            .bind(plugin_name)
            .bind(migration.version())
            .bind(migration.name())
            .execute(&mut *tx)
            .await?;

        // Commit transaction
        tx.commit().await?;
        Ok(())
    }

    pub async fn migrate(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        self.init_migration_table(pool).await?;
        self.init_user_table(pool).await?;

        for (plugin_name, plugin) in &self.plugins {
            let applied = self.get_applied_migrations(pool, plugin_name).await?;
            let pending = plugin
                .migrations()
                .into_iter()
                .filter(|m| !applied.contains(&m.version()));

            for migration in pending {
                self.apply_migration(pool, plugin_name, &*migration).await?;
            }
        }
        Ok(())
    }
}
