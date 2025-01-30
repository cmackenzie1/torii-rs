use async_trait::async_trait;
use sqlx::{Pool, Row, Sqlite};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Display;

use crate::error::Error;
use crate::migration::PluginMigration;

/// Represents the authentication method used to authenticate a user.
/// This is used for plugins to advertise which authentication methods they support.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum AuthMethod {
    EmailPassword,
    OIDC,
    WebAuthn,
}

/// Represents the credentials used to authenticate a user.
#[derive(Debug, Clone)]
pub enum AuthenticationRequest {
    /// Email and password credentials.
    EmailPassword { email: String, password: String },

    /// OIDC credentials
    OIDC {
        provider: String,
        id_token: Option<String>,
    },

    /// WebAuthn credentials
    WebAuthn,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum CreateUserParams {
    /// Create a user with an email and password.
    EmailPassword { email: String, password: String },

    /// Create a user with an OAuth2 provider and subject.
    OIDC { provider: String, subject: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(transparent)]
pub struct PluginId(String);

impl PluginId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl Display for PluginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[async_trait]
pub trait Plugin: Send + Sync + Any {
    /// The ID of the plugin.
    fn id(&self) -> PluginId;

    /// The name of the plugin.
    fn name(&self) -> &'static str;

    /// Setup the plugin. This is called when the plugin is registered and may be used to
    /// perform any necessary initialization. This method should not perform any migrations
    /// as the plugin manager will handle running migrations provided by the plugin.
    async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;

    /// Get the migrations for the plugin.
    fn migrations(&self) -> Vec<Box<dyn PluginMigration>>;

    /// Get the plugin as a `dyn Any` to allow for downcasting to the specific plugin type.
    fn as_any(&self) -> &dyn Any;
}

/// Manages a collection of plugins.
pub struct PluginManager {
    pub plugins: HashMap<PluginId, Box<dyn Plugin>>,
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

    /// Get a plugin by name.
    pub fn get_plugin<T: Plugin + 'static>(&self, id: &PluginId) -> Result<&T, Error> {
        self.plugins
            .get(id)
            .ok_or(Error::PluginNotFound(id.to_string()))?
            .as_any()
            .downcast_ref::<T>()
            .ok_or(Error::PluginTypeMismatch(id.to_string()))
    }

    /// Register a new plugin.
    pub fn register(&mut self, plugin: Box<dyn Plugin>) {
        self.plugins.insert(plugin.id(), plugin);
    }

    /// Setup all registered plugins. This should be called before any authentication
    /// is attempted.
    pub async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        for plugin in self.plugins.values() {
            plugin.setup(pool).await?;
        }
        Ok(())
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
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT,
                email TEXT,
                email_verified_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(email),
                UNIQUE(id)
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
        plugin_id: &PluginId,
    ) -> Result<Vec<i64>, Error> {
        let rows = sqlx::query(
            "SELECT version FROM torii_migrations WHERE plugin_name = ? ORDER BY version",
        )
        .bind(plugin_id)
        .fetch_all(pool)
        .await?;

        Ok(rows.iter().map(|row| row.get(0)).collect())
    }

    async fn apply_migration(
        &self,
        pool: &Pool<Sqlite>,
        plugin_id: &PluginId,
        migration: &dyn PluginMigration,
    ) -> Result<(), Error> {
        // Start transaction
        let mut tx = pool.begin().await?;

        // Apply migration
        migration.up(pool).await?;

        // Record migration
        sqlx::query("INSERT INTO torii_migrations (plugin_name, version, name) VALUES (?, ?, ?)")
            .bind(plugin_id)
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

        for (plugin_id, plugin) in &self.plugins {
            let applied = self.get_applied_migrations(pool, plugin_id).await?;
            let pending = plugin
                .migrations()
                .into_iter()
                .filter(|m| !applied.contains(&m.version()));

            for migration in pending {
                self.apply_migration(pool, plugin_id, &*migration).await?;
            }
        }
        Ok(())
    }
}
