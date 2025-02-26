//! # Torii
//!
//! Torii is a powerful authentication framework for Rust applications that gives you complete control
//! over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user
//! information in their cloud, Torii lets you own and manage your authentication stack while providing
//! modern auth features through a flexible plugin system.
//!
//! With Torii, you get powerful authentication capabilities like:
//! - Password-based authentication
//! - Social OAuth/OpenID Connect
//! - Passkey/WebAuthn support
//!
//! Combined with full data sovereignty and the ability to store user data wherever you choose.
//!
//! ## Storage Support
//!
//! Torii currently supports the following storage backends:
//! - SQLite
//! - PostgreSQL
//! - MySQL (In Development)
//!
//! ## Warning
//!
//! This project is in early development and is not production-ready. The API is subject to change
//! without notice. As this project has not undergone security audits, it should not be used in
//! production environments.
//!
//! ## Example
//!
//! ```rust,no_run
//! use torii::Torii;
//! use torii_storage_sqlite::SqliteStorage;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
//!     let session_storage = Arc::new(SqliteStorage::new(pool.clone()));
//!
//!     let torii = Torii::new(user_storage, session_storage)
//!         .with_password_plugin()
//!         .with_oauth_provider(Provider::google(
//!             "client_id",
//!             "client_secret",
//!             "redirect_uri"
//!         ))
//!         .with_passkey_plugin("rp_id", "rp_origin");
//! }
//! ```
use std::sync::Arc;

use torii_core::{
    PluginManager, SessionStorage,
    storage::{OAuthStorage, PasskeyStorage, PasswordStorage, Storage, UserStorage},
};

/// Re-export core types
pub use torii_core::{
    session::{Session, SessionId},
    user::{User, UserId},
};

/// Re-export auth plugins
#[cfg(feature = "password")]
pub use torii_auth_password::PasswordPlugin;

#[cfg(feature = "oauth")]
pub use torii_auth_oauth::{AuthorizationUrl, OAuthPlugin, providers::Provider};

#[cfg(feature = "passkey")]
pub use torii_auth_passkey::{PasskeyChallenge, PasskeyPlugin};

// Re-export storage backends
#[cfg(feature = "sqlite")]
pub use torii_storage_sqlite::SqliteStorage;

#[cfg(feature = "postgres")]
pub use torii_storage_postgres::PostgresStorage;

#[derive(Debug, thiserror::Error)]
pub enum ToriiError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("Auth error: {0}")]
    AuthError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// The main authentication coordinator that manages plugins and storage.
///
/// `Torii` acts as the central point for configuring and managing authentication in your application.
/// It coordinates between different authentication plugins and provides access to user/session storage.
///
/// The type parameters represent:
/// - `U`: The user storage implementation
/// - `S`: The session storage implementation
///
/// # Example
///
/// ```rust,no_run
/// use torii::Torii;
/// use torii_storage_sqlite::SqliteStorage;
/// use std::sync::Arc;
/// use sqlx::{Pool, Sqlite};
///
/// #[tokio::main]
/// async fn main() {
///     let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();
///     let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
///     let session_storage = Arc::new(SqliteStorage::new(pool.clone()));
///
///     // Create a new Torii instance and configure plugins
///     let torii = Torii::new(user_storage, session_storage)
///         .with_password_plugin();
///
///     // Use torii to manage authentication
///     let user = torii.get_user(&user_id).await?;
/// }
/// ```
pub struct Torii<U, S>
where
    U: UserStorage + Clone,
    S: SessionStorage + Clone,
{
    storage: Storage<U, S>,
    manager: PluginManager<U, S>,
}

impl<U, S> Torii<U, S>
where
    U: UserStorage + Clone,
    S: SessionStorage + Clone,
{
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            storage: Storage::new(user_storage.clone(), session_storage.clone()),
            manager: PluginManager::new(user_storage, session_storage),
        }
    }

    /// Get a user by their ID
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to retrieve
    ///
    /// # Returns
    ///
    /// Returns the user if found, otherwise `None`
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, ToriiError> {
        let user = self
            .storage
            .get_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;
        Ok(user)
    }

    /// Get a session by its ID
    ///
    /// # Arguments
    ///
    /// * `session_id`: The ID of the session to retrieve
    ///
    /// # Returns
    ///
    /// Returns the session if found, otherwise `None`
    pub async fn get_session(&self, session_id: &SessionId) -> Result<Option<Session>, ToriiError> {
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;
        Ok(session)
    }
}

#[cfg(feature = "password")]
impl<U, S> Torii<U, S>
where
    U: PasswordStorage + Clone,
    S: SessionStorage + Clone,
{
    /// Add a password plugin to the Torii instance
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the password plugin registered
    pub fn with_password_plugin(mut self) -> Self {
        let plugin = PasswordPlugin::new(self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    /// Register a user with a password
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to register
    /// * `password`: The password of the user to register
    ///
    /// # Returns
    ///
    /// Returns the registered user
    pub async fn register_user_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<User, ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<PasswordPlugin<U, S>>("password")
            .ok_or(ToriiError::PluginNotFound("password".to_string()))?;

        let user = password_plugin
            .register_user_with_password(email, password, None)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(user)
    }

    /// Login a user with a password
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to login
    /// * `password`: The password of the user to login
    ///
    /// # Returns
    ///
    /// Returns the user and session if the login is successful
    pub async fn login_user_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(User, Session), ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<PasswordPlugin<U, S>>("password")
            .ok_or(ToriiError::PluginNotFound("password".to_string()))?;

        let (user, session) = password_plugin
            .login_user_with_password(email, password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }

    /// Set a user's email as verified
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to set the email as verified
    pub async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), ToriiError> {
        self.storage
            .user_storage()
            .set_user_email_verified(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }
}

#[cfg(feature = "oauth")]
impl<U, S> Torii<U, S>
where
    U: OAuthStorage + Clone,
    S: SessionStorage + Clone,
{
    /// Add an OAuth provider to the Torii instance
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider to add
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the OAuth provider registered
    pub fn with_oauth_provider(mut self, provider: Provider) -> Self {
        let plugin = OAuthPlugin::new(provider, self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    /// Get the OAuth authorization URL for a provider
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider to get the authorization URL for
    ///
    /// # Returns
    ///
    /// Returns a [`AuthorizationUrl`] struct containing the authorization URL and CSRF state.
    pub async fn get_oauth_authorization_url(
        &self,
        provider: &str,
    ) -> Result<AuthorizationUrl, ToriiError> {
        let oauth_plugin = self
            .manager
            .get_plugin::<OAuthPlugin<U, S>>(provider)
            .ok_or(ToriiError::PluginNotFound(provider.to_string()))?;

        let url = oauth_plugin
            .get_authorization_url()
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(url)
    }

    /// Exchange an OAuth code for a user and session
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider to exchange the code for
    /// * `code`: The OAuth code to exchange
    /// * `csrf_state`: The CSRF state to exchange the code for
    ///
    /// # Returns
    ///
    /// Returns the user and session if the code is valid
    pub async fn exchange_oauth_code(
        &self,
        provider: &str,
        code: &str,
        csrf_state: &str,
    ) -> Result<(User, Session), ToriiError> {
        let oauth_plugin = self
            .manager
            .get_plugin::<OAuthPlugin<U, S>>(provider)
            .ok_or(ToriiError::PluginNotFound(provider.to_string()))?;

        let (user, session) = oauth_plugin
            .exchange_code(code.to_string(), csrf_state.to_string())
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }
}

#[cfg(feature = "passkey")]
impl<U, S> Torii<U, S>
where
    U: PasskeyStorage + Clone,
    S: SessionStorage + Clone,
{
    /// Add a passkey plugin to the Torii instance
    ///
    /// # Arguments
    ///
    /// * `rp_id`: The RP ID of the passkey. For example, `"localhost"`
    /// * `rp_origin`: The RP origin of the passkey. For example, `"https://localhost"`
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the passkey plugin registered
    pub fn with_passkey_plugin(mut self, rp_id: &str, rp_origin: &str) -> Self {
        let plugin = PasskeyPlugin::new(rp_id, rp_origin, self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    /// Begin a passkey registration
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to register
    ///
    /// # Returns
    ///
    /// Returns a [`PasskeyChallenge`] struct containing the challenge ID and challenge response.
    pub async fn begin_passkey_registration(
        &self,
        email: &str,
    ) -> Result<PasskeyChallenge, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        passkey_plugin
            .start_registration(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete a passkey registration
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to register
    /// * `challenge_id`: The challenge ID of the passkey
    /// * `challenge_response`: The challenge response of the passkey
    ///
    /// # Returns
    ///
    /// Returns the registered user and session if the registration is successful
    pub async fn complete_passkey_registration(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let (user, session) = passkey_plugin
            .complete_registration(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }

    /// Begin a passkey login
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to login
    ///
    /// # Returns
    ///
    /// Returns a [`PasskeyChallenge`] struct containing the challenge ID and challenge response.
    pub async fn begin_passkey_login(&self, email: &str) -> Result<PasskeyChallenge, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        passkey_plugin
            .start_login(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete a passkey login
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to login
    /// * `challenge_id`: The challenge ID of the passkey
    /// * `challenge_response`: The challenge response of the passkey
    ///
    /// # Returns
    ///
    /// Returns the user and session if the login is successful
    pub async fn complete_passkey_login(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let (user, session) = passkey_plugin
            .complete_login(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }
}
