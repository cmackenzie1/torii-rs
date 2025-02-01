use async_trait::async_trait;
use dashmap::DashMap;
use downcast_rs::{impl_downcast, DowncastSync};
use sqlx::{Pool, Row, Sqlite};
use std::any::{Any, TypeId};
use std::sync::Arc;

use crate::error::Error;
use crate::migration::PluginMigration;
use crate::migrations::{CreateSessionsTable, CreateUsersTable};

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

    /// Get the dependencies of this plugin.
    /// Returns a list of plugin names that must be initialized before this one.
    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new() // Default to no dependencies
    }

    /// Setup the plugin. This is called when the plugin is registered and may be used to
    /// perform any necessary initialization. This method should not perform any migrations
    /// as the plugin manager will handle running migrations provided by the plugin.
    async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
        Ok(())
    }

    /// Get the migrations for the plugin.
    fn migrations(&self) -> Vec<Box<dyn PluginMigration>>;
}
impl_downcast!(sync Plugin);

/// Manages a collection of plugins.
pub struct PluginManager {
    plugins: DashMap<TypeId, Arc<dyn Plugin>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    /// Creates a new empty plugin manager.
    ///
    /// # Example
    /// ```
    /// use torii_core::PluginManager;
    ///
    /// let plugin_manager = PluginManager::new();
    /// ```
    pub fn new() -> Self {
        Self {
            plugins: DashMap::new(),
        }
    }

    /// Gets a plugin instance by its type.
    ///
    /// # Example
    /// ```
    /// use torii_core::{PluginManager, Plugin};
    ///
    /// struct MyPlugin;
    /// impl Plugin for MyPlugin { /* ... */ }
    ///
    /// let mut plugin_manager = PluginManager::new();
    /// plugin_manager.register(MyPlugin);
    ///
    /// let plugin = plugin_manager.get_plugin::<MyPlugin>();
    /// ```
    pub fn get_plugin<T: Plugin + 'static>(&self) -> Option<Arc<T>> {
        let plugin = self.plugins.get(&TypeId::of::<T>())?;
        plugin.value().clone().downcast_arc::<T>().ok()
    }

    /// Registers a new plugin with the plugin manager.
    ///
    /// # Example
    /// ```
    /// use torii_core::{PluginManager, Plugin};
    ///
    /// struct MyPlugin;
    /// impl Plugin for MyPlugin { /* ... */ }
    ///
    /// let mut plugin_manager = PluginManager::new();
    /// plugin_manager.register(MyPlugin);
    /// ```
    pub fn register<T: Plugin + 'static>(&mut self, plugin: T) {
        let plugin = Arc::new(plugin);
        let type_id = TypeId::of::<T>();
        self.plugins.insert(type_id, plugin.clone());
        tracing::info!("Registered plugin: {}", plugin.name());
    }

    /// Sets up all registered plugins in dependency order.
    ///
    /// # Example
    /// ```
    /// use torii_core::{PluginManager, Plugin};
    /// use sqlx::{Pool, Sqlite};
    ///
    /// async fn setup(pool: &Pool<Sqlite>) {
    ///     let plugin_manager = PluginManager::new();
    ///     plugin_manager.setup(pool).await.expect("Failed to setup plugins");
    /// }
    /// ```
    pub async fn setup(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        let ordered = self.get_ordered_plugins()?;
        for plugin_id in ordered {
            let plugin = self.plugins.get(&plugin_id).expect("Plugin not found");
            plugin.value().setup(pool).await?;
            tracing::info!("Setup plugin: {}", plugin.value().name());
        }
        Ok(())
    }

    /// Initializes the migrations table if it doesn't exist.
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

    /// Gets a list of already applied migration versions for a plugin.
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

    /// Applies a single migration for a plugin.
    async fn apply_migration(
        &self,
        pool: &Pool<Sqlite>,
        plugin_name: &str,
        migration: &dyn PluginMigration,
    ) -> Result<(), Error> {
        let mut tx = pool.begin().await?;

        tracing::info!(
            plugin.name = plugin_name,
            version = migration.version(),
            "Applying migration"
        );

        migration.up(pool).await?;

        sqlx::query("INSERT INTO torii_migrations (plugin_name, version, name) VALUES (?, ?, ?)")
            .bind(plugin_name)
            .bind(migration.version())
            .bind(migration.name())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        tracing::info!(
            plugin.name = plugin_name,
            version = migration.version(),
            "Applied migration"
        );

        Ok(())
    }

    /// Applies all migrations for a specific plugin that haven't been applied yet.
    async fn apply_migrations_for_plugin(
        &self,
        pool: &Pool<Sqlite>,
        plugin_name: &str,
        migrations: Vec<Box<dyn PluginMigration>>,
    ) -> Result<(), Error> {
        let applied = self.get_applied_migrations(pool, plugin_name).await?;

        for migration in migrations {
            if !applied.contains(&migration.version()) {
                self.apply_migration(pool, plugin_name, &*migration).await?;
            }
        }
        Ok(())
    }

    /// Applies core migrations that are required for the system to function.
    async fn apply_core_migrations(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        let core_migrations: Vec<Box<dyn PluginMigration>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            // Add other core migrations here
        ];

        self.apply_migrations_for_plugin(pool, "core", core_migrations)
            .await
    }

    /// Gets a list of plugin TypeIds in dependency order.
    fn get_ordered_plugins(&self) -> Result<Vec<TypeId>, Error> {
        let mut ordered = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut temp_visited = std::collections::HashSet::new();

        for plugin_id in self.plugins.iter().map(|p| *p.key()) {
            self.visit_plugin(plugin_id, &mut ordered, &mut visited, &mut temp_visited)?;
        }

        Ok(ordered)
    }

    /// Helper function for topological sort of plugins.
    fn visit_plugin(
        &self,
        plugin_id: TypeId,
        ordered: &mut Vec<TypeId>,
        visited: &mut std::collections::HashSet<TypeId>,
        temp_visited: &mut std::collections::HashSet<TypeId>,
    ) -> Result<(), Error> {
        if temp_visited.contains(&plugin_id) {
            return Err(Error::Plugin("Circular dependency detected".into()));
        }
        if visited.contains(&plugin_id) {
            return Ok(());
        }

        temp_visited.insert(plugin_id);

        let plugin = self.plugins.get(&plugin_id).expect("Plugin not found");

        for dep_name in plugin.value().dependencies() {
            let dep_id = self
                .plugins
                .iter()
                .find(|p| p.value().name() == dep_name)
                .map(|p| *p.key())
                .ok_or_else(|| Error::Plugin(format!("Dependency '{}' not found", dep_name)))?;

            self.visit_plugin(dep_id, ordered, visited, temp_visited)?;
        }

        temp_visited.remove(&plugin_id);
        visited.insert(plugin_id);
        ordered.push(plugin_id);

        Ok(())
    }

    /// Runs all pending migrations for all plugins in dependency order.
    ///
    /// # Example
    /// ```
    /// use torii_core::PluginManager;
    /// use sqlx::{Pool, Sqlite};
    ///
    /// async fn migrate(pool: &Pool<Sqlite>) {
    ///     let plugin_manager = PluginManager::new();
    ///     plugin_manager.migrate(pool).await.expect("Failed to run migrations");
    /// }
    /// ```
    pub async fn migrate(&self, pool: &Pool<Sqlite>) -> Result<(), Error> {
        self.init_migration_table(pool).await?;
        self.apply_core_migrations(pool).await?;

        let ordered_plugins = self.get_ordered_plugins()?;
        for plugin_id in ordered_plugins {
            let plugin = self.plugins.get(&plugin_id).expect("Plugin not found");
            let migrations = plugin.value().migrations();
            self.apply_migrations_for_plugin(pool, plugin.value().name(), migrations)
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct TestPlugin;

    #[async_trait]
    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            "test"
        }

        async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
            Ok(())
        }

        fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
            vec![]
        }
    }

    impl TestPlugin {
        fn new() -> Self {
            Self
        }
    }

    #[tokio::test]
    async fn test_plugin_manager() {
        let mut plugin_manager = PluginManager::new();
        plugin_manager.register(TestPlugin::new());
        let plugin = plugin_manager.get_plugin::<TestPlugin>().unwrap();
        assert_eq!(plugin.name(), "test");
    }

    async fn setup_test_db() -> Pool<Sqlite> {
        // Create an in-memory database for testing
        let pool = Pool::connect("sqlite::memory:").await.unwrap();
        pool
    }

    #[tokio::test]
    async fn test_basic_setup() {
        let pool = setup_test_db().await;
        let plugin_manager = PluginManager::new();

        // This should now work without duplicate migration errors
        plugin_manager
            .migrate(&pool)
            .await
            .expect("Migration failed");
    }
}
