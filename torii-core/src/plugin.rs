use async_trait::async_trait;
use downcast_rs::{impl_downcast, DowncastSync};
use sqlx::{Pool, Row, Sqlite};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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

#[async_trait]
pub trait Plugin: Any + Send + Sync + DowncastSync {
    /// The name of the plugin.
    fn name(&self) -> &'static str;

    /// Setup the plugin. This is called when the plugin is registered and may be used to
    /// perform any necessary initialization. This method should not perform any migrations
    /// as the plugin manager will handle running migrations provided by the plugin.
    async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error>;

    /// Get the migrations for the plugin.
    fn migrations(&self) -> Vec<Box<dyn PluginMigration>>;
}
impl_downcast!(sync Plugin);

/// Manages a collection of plugins.
pub struct PluginManager {
    pub plugins: RwLock<HashMap<TypeId, Arc<dyn Plugin>>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
        }
    }

    /// Get a plugin by type.
    pub fn get_plugin<T: Plugin + 'static>(&self) -> Option<Arc<T>> {
        let plugins = self.plugins.read().unwrap();
        let plugin = plugins.get(&TypeId::of::<T>())?;
        plugin.clone().downcast_arc::<T>().ok()
    }

    /// Register a new plugin.
    pub fn register<T: Plugin + 'static>(&self, plugin: T) {
        let plugin = Arc::new(plugin);
        let type_id = TypeId::of::<T>();
        self.plugins.write().unwrap().insert(type_id, plugin);
        tracing::info!(
            "Registered plugin: {}",
            self.get_plugin::<T>().unwrap().name()
        );
    }

    /// Setup all registered plugins. This should be called before any authentication
    /// is attempted.
    pub async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        for plugin in self.plugins.read().unwrap().values() {
            plugin.setup(pool).await?;
            tracing::info!("Setup plugin: {}", plugin.name());
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
        tracing::info!("Initialized migration table");
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
        tracing::info!("Initialized user table");
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
        tracing::info!(
            plugin.name = plugin_name,
            version = migration.version(),
            "Applying migration"
        );
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
        tracing::info!(
            plugin.name = plugin_name,
            version = migration.version(),
            "Applied migration"
        );
        Ok(())
    }

    pub async fn migrate(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        // TODO: these should be migrations themselves -- maybe  init plugin?
        self.init_migration_table(pool).await?;
        self.init_user_table(pool).await?;

        for plugin in self.plugins.read().unwrap().values() {
            let applied = self.get_applied_migrations(pool, plugin.name()).await?;
            let pending = plugin
                .migrations()
                .into_iter()
                .filter(|m| !applied.contains(&m.version()));

            for migration in pending {
                self.apply_migration(pool, plugin.name(), &*migration)
                    .await?;
            }
        }
        Ok(())
    }
}
