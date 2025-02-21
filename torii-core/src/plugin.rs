//! Plugin system
//!
//! This module contains the core plugin system including migrations.
//!
//! See [`Plugin`] trait for the required methods for a plugin.
//!
//! See [`PluginManager`] for the plugin manager which is responsible for managing the plugins.
use dashmap::DashMap;
use std::any::Any;
use std::sync::Arc;
use std::time::Duration;

use crate::{
    auth::AuthPlugin,
    storage::{SessionStorage, Storage, UserStorage},
};

pub trait Plugin: Any + Send + Sync {
    /// The unique name of the plugin instance.
    fn name(&self) -> String;
}

/// Manages a collection of plugins.
pub struct PluginManager<U: UserStorage, S: SessionStorage> {
    auth_plugins: DashMap<String, Arc<dyn AuthPlugin>>,
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
            auth_plugins: DashMap::new(),
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
    /// let plugin = plugin_manager.get_auth_plugin::<MyPlugin>("my_plugin");
    /// ```
    pub fn get_auth_plugin<T: AuthPlugin + 'static>(&self, name: &str) -> Option<Arc<T>> {
        let plugin = self.auth_plugins.get(name)?;
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
    pub fn register_auth_plugin<T: AuthPlugin + 'static>(&mut self, plugin: T) {
        let name = plugin.name();
        let plugin = Arc::new(plugin);
        self.auth_plugins.insert(name.clone(), plugin.clone());
        tracing::info!(plugin.name = name, "Registered plugin");
    }

    pub fn storage(&self) -> &Storage<U, S> {
        &self.storage
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
    use async_trait::async_trait;

    use crate::{
        AuthResponse, Credentials, Error, NewUser, Session, User, UserId, session::SessionId,
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct TestPlugin;

    impl Plugin for TestPlugin {
        fn name(&self) -> String {
            "test".to_string()
        }
    }

    #[async_trait]
    impl AuthPlugin for TestPlugin {
        fn auth_method(&self) -> String {
            "test".to_string()
        }

        async fn register(&self, _credentials: &Credentials) -> Result<AuthResponse, Error> {
            todo!()
        }

        async fn authenticate(&self, _credentials: &Credentials) -> Result<AuthResponse, Error> {
            todo!()
        }

        async fn validate_session(&self, _session: &Session) -> Result<bool, Error> {
            todo!()
        }

        async fn logout(&self, _session: &Session) -> Result<(), Error> {
            todo!()
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

        async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
            Ok(self.users.get(id).map(|u| u.clone()))
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
                .name(None)
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

        async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
            self.users.remove(id);
            Ok(())
        }
    }

    #[async_trait]
    impl SessionStorage for TestStorage {
        type Error = Error;

        async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Self::Error> {
            Ok(self.sessions.get(id).map(|s| s.clone()))
        }

        async fn create_session(&self, session: &Session) -> Result<Session, Self::Error> {
            self.sessions.insert(session.id.clone(), session.clone());
            Ok(session.clone())
        }

        async fn delete_session(&self, id: &SessionId) -> Result<(), Self::Error> {
            self.sessions.remove(id);
            Ok(())
        }

        async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Self::Error> {
            self.sessions.retain(|_, s| s.user_id != *user_id);
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
        plugin_manager.register_auth_plugin(TestPlugin::new());
        let plugin = plugin_manager
            .get_auth_plugin::<TestPlugin>("test")
            .unwrap();
        assert_eq!(plugin.name(), "test");
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
        assert!(
            session_storage
                .get_session(&SessionId::new("expired"))
                .await
                .expect("Failed to get session")
                .is_none()
        );
        assert!(
            session_storage
                .get_session(&SessionId::new("valid"))
                .await
                .expect("Failed to get session")
                .is_some()
        );
    }
}
