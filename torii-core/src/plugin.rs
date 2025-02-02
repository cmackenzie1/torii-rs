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
use std::any::{Any, TypeId};
use std::sync::Arc;

use crate::error::Error;
use crate::storage::{SessionStorage, UserStorage};

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
pub trait Plugin<U: UserStorage, S: SessionStorage>: Any + Send + Sync + DowncastSync {
    /// The name of the plugin.
    fn name(&self) -> &'static str;

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
pub struct PluginManager<U: UserStorage + ?Sized, S: SessionStorage + ?Sized> {
    plugins: DashMap<TypeId, Arc<dyn Plugin<U, S>>>,
    user_storage: Arc<U>,
    session_storage: Arc<S>,
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
            user_storage,
            session_storage,
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
    pub fn get_plugin<T: Plugin<U, S> + 'static>(&self) -> Option<Arc<T>> {
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
    pub fn register<T: Plugin<U, S> + 'static>(&mut self, plugin: T) {
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
    pub async fn setup(&self) -> Result<(), Error> {
        let ordered = self.get_ordered_plugins()?;
        for plugin_id in ordered {
            let plugin = self.plugins.get(&plugin_id).expect("Plugin not found");
            plugin
                .value()
                .setup(&self.user_storage, &self.session_storage)
                .await?;
            tracing::info!("Setup plugin: {}", plugin.value().name());
        }
        Ok(())
    }

    pub fn user_storage(&self) -> Arc<U> {
        self.user_storage.clone()
    }

    pub fn session_storage(&self) -> Arc<S> {
        self.session_storage.clone()
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
}

#[cfg(test)]
mod tests {

    use crate::{session::SessionId, NewUser, Session, User, UserId};

    use super::*;

    #[derive(Debug, Clone)]
    struct TestPlugin;

    #[async_trait]
    impl Plugin<TestStorage, TestStorage> for TestPlugin {
        fn name(&self) -> &'static str {
            "test"
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

        async fn get_user(&self, id: &str) -> Result<User, Self::Error> {
            self.users
                .get(&UserId::new(id))
                .map(|u| u.clone())
                .ok_or_else(|| Error::UserNotFound)
        }

        async fn get_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
            self.users
                .iter()
                .find(|u| u.email == email)
                .map(|u| u.clone())
                .ok_or_else(|| Error::UserNotFound)
        }

        async fn create_user(&self, new_user: &NewUser) -> Result<User, Self::Error> {
            let id = UserId::new_random();
            let user = User {
                id: id.clone(),
                email: new_user.email.clone(),
                created_at: chrono::Utc::now(),
                email_verified_at: None,
                name: "test".to_string(),
                updated_at: chrono::Utc::now(),
            };
            self.users.insert(id, user.clone());
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

        async fn get_session(&self, id: &str) -> Result<Session, Self::Error> {
            self.sessions
                .get(&SessionId::new(id))
                .map(|s| s.clone())
                .ok_or_else(|| Error::SessionNotFound)
        }

        async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
            self.sessions.insert(session.id.clone(), session.clone());
            Ok(session.clone())
        }

        async fn delete_session(&self, id: &str) -> Result<(), Self::Error> {
            self.sessions.remove(&SessionId::new(id));
            Ok(())
        }
    }

    // Setup test storage for testing
    fn setup_test_storage() -> (TestStorage, TestStorage) {
        let user_storage = TestStorage::new();
        let session_storage = TestStorage::new();
        (user_storage, session_storage)
    }

    #[tokio::test]
    async fn test_plugin_manager() {
        let (user_storage, session_storage) = setup_test_storage();
        let mut plugin_manager = PluginManager::new(user_storage, session_storage);
        plugin_manager.register(TestPlugin::new());
        let plugin = plugin_manager.get_plugin::<TestPlugin>().unwrap();
        assert_eq!(plugin.name(), "test");
    }

    #[tokio::test]
    async fn test_basic_setup() {
        let (user_storage, session_storage) = setup_test_storage();
        let plugin_manager = PluginManager::new(user_storage, session_storage);

        // This should now work without duplicate migration errors
        plugin_manager.setup().await.expect("Setup failed");
    }
}
