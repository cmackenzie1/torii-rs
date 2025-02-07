//! Plugin system
//!
//! This module contains the core plugin system including migrations.
//!
//! See [`Plugin`] trait for the required methods for a plugin.
//!
//! See [`PluginManager`] for the plugin manager which is responsible for managing the plugins.
use async_trait::async_trait;
use dashmap::DashMap;
use downcast_rs::{impl_downcast, DowncastSync};
use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use crate::error::Error;
use crate::storage::{SessionStorage, Storage, UserStorage};

#[async_trait]
pub trait Plugin<U: UserStorage, S: SessionStorage>: Any + Send + Sync + DowncastSync {
    /// The unique name of the plugin instance.
    /// For OIDC plugins, this should be the provider name (e.g. "google", "github")
    fn name(&self) -> String;

    /// Get the dependencies of this plugin.
    /// Returns a list of plugin names that must be initialized before this one.
    fn dependencies(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Setup the plugin. This is called when the plugin is registered and may be used to
    /// perform any necessary initialization of the user and session storage. Migrations
    /// should be handled outside of the runtime (i.e, using sqlx::migrate with whatever storage
    /// backend you are using).
    async fn setup(&self, _user_storage: &U, _session_storage: &S) -> Result<(), Error> {
        Ok(())
    }
}
impl_downcast!(sync Plugin<U, S> where U: UserStorage, S: SessionStorage);

/// Manages a collection of plugins.
pub struct PluginManager<U: UserStorage, S: SessionStorage> {
    plugins: DashMap<String, Arc<dyn Plugin<U, S>>>,
    storage: Storage<U, S>,
}

impl<U: UserStorage, S: SessionStorage> PluginManager<U, S> {
    /// Creates a new empty plugin manager.
    ///
    /// # Example
    /// ```
    /// use torii_core::PluginManager;
    ///
    /// let plugin_manager = PluginManager::new();
    /// ```
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            plugins: DashMap::new(),
            storage: Storage::new(user_storage, session_storage),
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
    /// let plugin = plugin_manager.get_plugin::<MyPlugin>("my_plugin");
    /// ```
    pub fn get_plugin<T: Plugin<U, S> + 'static>(&self, name: &str) -> Option<Arc<T>> {
        let plugin = self.plugins.get(name)?;
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
    pub fn register<T: Plugin<U, S> + 'static>(&mut self, plugin: T) {
        let name = plugin.name();
        let plugin = Arc::new(plugin);
        self.plugins.insert(name.clone(), plugin.clone());
        tracing::info!(plugin.name = name, "Registered plugin");
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
    pub async fn setup(&self) -> Result<(), Error> {
        let ordered = self.get_ordered_plugins()?;
        for plugin_id in ordered {
            let plugin = self.plugins.get(&plugin_id).expect("Plugin not found");
            plugin
                .value()
                .setup(
                    &self.storage.user_storage(),
                    &self.storage.session_storage(),
                )
                .await?;
            tracing::info!("Setup plugin: {}", plugin.value().name());
        }
        Ok(())
    }

    pub fn storage(&self) -> &Storage<U, S> {
        &self.storage
    }

    /// Gets a list of plugin TypeIds in dependency order.
    fn get_ordered_plugins(&self) -> Result<Vec<String>, Error> {
        let mut ordered = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut temp_visited = std::collections::HashSet::new();

        for plugin_id in self.plugins.iter().map(|p| p.key().clone()) {
            self.visit_plugin(&plugin_id, &mut ordered, &mut visited, &mut temp_visited)?;
        }

        Ok(ordered)
    }

    /// Helper function for topological sort of plugins.
    fn visit_plugin(
        &self,
        plugin_id: &str,
        ordered: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
        temp_visited: &mut std::collections::HashSet<String>,
    ) -> Result<(), Error> {
        if temp_visited.contains(plugin_id) {
            return Err(Error::Plugin("Circular dependency detected".into()));
        }
        if visited.contains(plugin_id) {
            return Ok(());
        }

        temp_visited.insert(plugin_id.to_string());

        let plugin = self.plugins.get(plugin_id).expect("Plugin not found");

        for dep_name in plugin.value().dependencies() {
            let dep_id = self
                .plugins
                .iter()
                .find(|p| p.value().name() == dep_name)
                .map(|p| p.key().clone())
                .ok_or_else(|| Error::Plugin(format!("Dependency '{}' not found", dep_name)))?;

            self.visit_plugin(&dep_id, ordered, visited, temp_visited)?;
        }

        temp_visited.remove(&plugin_id.to_string());
        visited.insert(plugin_id.to_string());
        ordered.push(plugin_id.to_string());

        Ok(())
    }

    /// Starts a background task to cleanup expired sessions.
    ///
    /// # Example
    /// ```
    /// use torii_core::PluginManager;
    /// use torii_core::SessionCleanupConfig;
    ///
    /// let plugin_manager = PluginManager::new();
    /// plugin_manager.start_session_cleanup_task(SessionCleanupConfig::default());
    /// ```
    pub async fn start_session_cleanup_task(&self, config: SessionCleanupConfig) {
        let storage = self.storage.session_storage().clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(config.interval);
            loop {
                interval.tick().await;
                if let Err(e) = storage.cleanup_expired_sessions().await {
                    tracing::error!("Failed to cleanup sessions: {}", e);
                }
            }
        });
    }
}

#[derive(Clone)]
pub struct SessionCleanupConfig {
    /// How often to run the cleanup task (default: 1 hour)
    pub interval: Duration,
    /// Maximum age of sessions before they're cleaned up (default: 30 days)
    pub max_session_age: Duration,
}

impl Default for SessionCleanupConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600),           // 1 hour
            max_session_age: Duration::from_secs(2592000), // 30 days
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{session::SessionId, NewUser, Session, User, UserId};

    use super::*;

    #[derive(Debug, Clone)]
    struct TestPlugin;

    #[async_trait]
    impl Plugin<TestStorage, TestStorage> for TestPlugin {
        fn name(&self) -> String {
            "test".to_string()
        }

        async fn setup(
            &self,
            _user_storage: &TestStorage,
            _session_storage: &TestStorage,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    impl TestPlugin {
        fn new() -> Self {
            Self
        }
    }

    struct TestStorage {
        users: DashMap<UserId, User>,
        sessions: DashMap<SessionId, Session>,
    }

    impl TestStorage {
        fn new() -> Self {
            Self {
                users: DashMap::new(),
                sessions: DashMap::new(),
            }
        }
    }

    #[async_trait]
    impl UserStorage for TestStorage {
        type Error = Error;

        async fn get_user(&self, id: &str) -> Result<Option<User>, Self::Error> {
            Ok(self.users.get(&UserId::new(id)).map(|u| u.clone()))
        }

        async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
            Ok(self
                .users
                .iter()
                .find(|u| u.email == email)
                .map(|u| u.clone()))
        }

        async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
            match self.get_user_by_email(email).await {
                Ok(Some(user)) => Ok(user),
                Ok(None) => {
                    self.create_user(
                        &NewUser::builder()
                            .id(UserId::new_random())
                            .email(email.to_string())
                            .build()
                            .unwrap(),
                    )
                    .await
                }
                Err(e) => Err(e),
            }
        }

        async fn create_user(&self, new_user: &NewUser) -> Result<User, Self::Error> {
            let user = User::builder()
                .email(new_user.email.clone())
                .created_at(chrono::Utc::now())
                .email_verified_at(None)
                .name("test".to_string())
                .updated_at(chrono::Utc::now())
                .build()
                .unwrap();
            self.users.insert(user.id.clone(), user.clone());
            Ok(user)
        }

        async fn update_user(&self, user: &User) -> Result<User, Self::Error> {
            self.users.insert(user.id.clone(), user.clone());
            Ok(user.clone())
        }

        async fn delete_user(&self, id: &str) -> Result<(), Self::Error> {
            self.users.remove(&UserId::new(id));
            Ok(())
        }
    }

    #[async_trait]
    impl SessionStorage for TestStorage {
        type Error = Error;

        async fn get_session(&self, id: &str) -> Result<Option<Session>, Self::Error> {
            Ok(self.sessions.get(&SessionId::new(id)).map(|s| s.clone()))
        }

        async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
            self.sessions.insert(session.id.clone(), session.clone());
            Ok(session.clone())
        }

        async fn delete_session(&self, id: &str) -> Result<(), Self::Error> {
            self.sessions.remove(&SessionId::new(id));
            Ok(())
        }

        async fn delete_sessions_for_user(&self, user_id: &str) -> Result<(), Self::Error> {
            let user_id = UserId::new(user_id);
            self.sessions.retain(|_, s| s.user_id != user_id);
            Ok(())
        }

        async fn cleanup_expired_sessions(&self) -> Result<(), Self::Error> {
            let now = chrono::Utc::now();
            self.sessions.retain(|_, s| s.expires_at > now);
            Ok(())
        }
    }

    // Setup test storage for testing
    fn setup_test_storage() -> (Arc<TestStorage>, Arc<TestStorage>) {
        let user_storage = Arc::new(TestStorage::new());
        let session_storage = Arc::new(TestStorage::new());
        (user_storage, session_storage)
    }

    #[tokio::test]
    async fn test_plugin_manager() {
        let (user_storage, session_storage) = setup_test_storage();
        let mut plugin_manager = PluginManager::new(user_storage, session_storage);
        plugin_manager.register(TestPlugin::new());
        let plugin = plugin_manager.get_plugin::<TestPlugin>("test").unwrap();
        assert_eq!(plugin.name(), "test");
    }

    #[tokio::test]
    async fn test_basic_setup() {
        let (user_storage, session_storage) = setup_test_storage();
        let mut plugin_manager = PluginManager::new(user_storage, session_storage);
        plugin_manager.register(TestPlugin::new());

        // This should now work without duplicate migration errors
        plugin_manager.setup().await.expect("Setup failed");
    }

    #[tokio::test]
    async fn test_session_cleanup() {
        let (user_storage, session_storage) = setup_test_storage();
        let plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());

        // Create an expired session
        let expired_session = Session {
            id: SessionId::new("expired"),
            user_id: UserId::new("test"),
            user_agent: None,
            ip_address: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
        };
        session_storage
            .create_session(&expired_session)
            .await
            .expect("Failed to create expired session");

        // Create a valid session
        let valid_session = Session {
            id: SessionId::new("valid"),
            user_id: UserId::new("test"),
            user_agent: None,
            ip_address: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        };
        session_storage
            .create_session(&valid_session)
            .await
            .expect("Failed to create valid session");

        // Configure cleanup to run frequently
        let config = SessionCleanupConfig {
            interval: Duration::from_millis(100),
            max_session_age: Duration::from_secs(3600),
        };

        // Start cleanup task
        plugin_manager.start_session_cleanup_task(config).await;

        // Wait for cleanup to run
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify expired session was removed but valid session remains
        assert!(session_storage
            .get_session("expired")
            .await
            .expect("Failed to get session")
            .is_none());
        assert!(session_storage
            .get_session("valid")
            .await
            .expect("Failed to get session")
            .is_some());
    }
}
