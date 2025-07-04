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
//! - Magic Link authentication
//!
//! Combined with full data sovereignty and the ability to store user data wherever you choose.
//!
//! ## Storage Support
//!
//! Torii currently supports the following storage backends:
//! - SQLite
//! - Postgres
//! - MySQL
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
//!     use torii_auth_oauth::providers::Provider;
//!     let storage = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
//!
//!     let torii = Torii::new(storage.clone())
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

use chrono::Duration;
use torii_core::{
    DefaultUserManager, PluginManager, UserManager,
    session::{DefaultSessionManager, JwtSessionManager, SessionManager},
    storage::{PasswordStorage, SessionStorage, UserStorage},
};

/// Re-export core types from torii_core
///
/// These types are commonly used when working with the Torii API.
pub use torii_core::{
    session::{JwtConfig, Session, SessionToken},
    storage::MagicToken,
    user::{User, UserId},
};

/// Re-export authentication plugins
///
/// These plugins provide various authentication methods when the corresponding feature is enabled.
#[cfg(feature = "password")]
pub use torii_auth_password::PasswordPlugin;

#[cfg(feature = "oauth")]
pub use torii_auth_oauth::{AuthorizationUrl, OAuthPlugin, providers::Provider};

#[cfg(feature = "passkey")]
pub use torii_auth_passkey::{
    ChallengeId, PasskeyAuthPlugin, PasskeyCredentialCreationOptions,
    PasskeyCredentialRequestOptions, PasskeyLoginCompletion, PasskeyLoginRequest, PasskeyPlugin,
    PasskeyRegistrationCompletion, PasskeyRegistrationRequest,
};

#[cfg(feature = "magic-link")]
pub use torii_auth_magic_link::MagicLinkPlugin;

/// Re-export storage backends
///
/// These storage implementations are available when the corresponding feature is enabled.
#[cfg(feature = "sqlite")]
pub use torii_storage_sqlite::SqliteStorage;

#[cfg(feature = "postgres")]
pub use torii_storage_postgres::PostgresStorage;

#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
pub use torii_storage_seaorm::SeaORMStorage;

/// Errors that can occur when using Torii.
///
/// This enum represents the various error types that can occur when using the Torii authentication framework.
#[derive(Debug, thiserror::Error)]
pub enum ToriiError {
    /// Error when a plugin is not found
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    /// Error during authentication
    #[error("Auth error: {0}")]
    AuthError(String),
    /// Error when interacting with storage
    #[error("Storage error: {0}")]
    StorageError(String),
}

/// The configuration for a session.
///
/// This struct is used to configure the session for a user.
/// It includes settings for session expiration and JWT options.
///
/// # Example
///
/// ```rust
/// use torii::SessionConfig;
///
/// let config = SessionConfig::default();
/// ```
pub struct SessionConfig {
    /// The duration until the session expires
    pub expires_in: Duration,
    /// JWT configuration (if using JWT sessions)
    pub jwt_config: Option<JwtConfig>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::days(30),
            jwt_config: None,
        }
    }
}

impl SessionConfig {
    /// Create a new session config with JWT support
    ///
    /// # Arguments
    ///
    /// * `jwt_config` - The JWT configuration to use
    ///
    /// # Returns
    ///
    /// The updated session configuration with JWT support enabled
    pub fn with_jwt(mut self, jwt_config: JwtConfig) -> Self {
        self.jwt_config = Some(jwt_config);
        self
    }

    /// Set the session expiration time
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration until the session expires
    ///
    /// # Returns
    ///
    /// The updated session configuration with the new expiration time
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }
}

/// The main authentication coordinator that manages plugins and storage.
///
/// `Torii` acts as the central point for configuring and managing authentication in your application.
/// It coordinates between different authentication plugins and provides access to user/session storage.
///
/// The type parameters represent:
/// - `US`: The storage implementation for user data
/// - `SS`: The storage implementation for session data (defaults to the same as US)
///
/// # Example
///
/// ```rust,no_run
/// use torii::Torii;
/// use torii_storage_sqlite::SqliteStorage;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() {
///     let storage = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
///
///     // Create a new Torii instance with just the storage
///     let torii = Torii::new(storage.clone())
///         .with_password_plugin();
///
///     // Use torii to manage authentication
///     let user = torii.get_user(&user_id).await?;
/// }
/// ```
pub struct Torii<US, SS = US>
where
    US: UserStorage + 'static,
    SS: SessionStorage + 'static,
{
    user_storage: Arc<US>,
    session_storage: Arc<SS>,
    user_manager: Arc<dyn UserManager + Send + Sync>,
    session_manager: Arc<dyn SessionManager + Send + Sync>,
    manager: PluginManager<US, SS>,
    session_config: SessionConfig,
}

impl<S> Torii<S, S>
where
    S: UserStorage + SessionStorage + 'static,
{
    /// Create a new Torii instance with a single storage backend
    ///
    /// This constructor initializes Torii with default user and session managers
    /// using the provided storage for both user and session data.
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage implementation for both user and session data
    ///
    /// # Returns
    ///
    /// A new Torii instance with default managers
    pub fn new(storage: Arc<S>) -> Self {
        let user_manager: Arc<dyn UserManager + Send + Sync> =
            Arc::new(DefaultUserManager::new(storage.clone()));
        let session_manager: Arc<dyn SessionManager + Send + Sync> =
            Arc::new(DefaultSessionManager::new(storage.clone()));
        let manager = PluginManager::new(storage.clone(), storage.clone());

        Self {
            user_storage: storage.clone(),
            session_storage: storage,
            user_manager,
            session_manager,
            manager,
            session_config: SessionConfig::default(),
        }
    }

    /// Configure Torii to use JWT sessions with HS256 or RS256 signing algorithm
    ///
    /// This method enables stateless sessions that don't require database lookups for session validation.
    /// The trade-off is that sessions are not revocable, and a compromised JWT cannot be revoked,
    /// so a short lifetime is recommended.
    ///
    /// # Arguments
    ///
    /// * `jwt_config` - The JWT configuration settings including secret key or RSA keys
    ///
    /// # Returns
    ///
    /// A new Torii instance configured to use JWT sessions
    pub fn with_jwt_sessions(self, jwt_config: JwtConfig) -> Self {
        let user_manager = self.user_manager;
        let session_manager: Arc<dyn SessionManager + Send + Sync> =
            Arc::new(JwtSessionManager::new(jwt_config.clone()));
        let manager = PluginManager::new(self.user_storage.clone(), self.session_storage.clone());

        Self {
            user_storage: self.user_storage,
            session_storage: self.session_storage,
            user_manager,
            session_manager,
            manager,
            session_config: self.session_config.with_jwt(jwt_config),
        }
    }
}

impl<US, SS> Torii<US, SS>
where
    US: UserStorage + 'static,
    SS: SessionStorage + 'static,
{
    /// Create a new Torii instance with separate storage backends
    ///
    /// This constructor initializes Torii with default user and session managers
    /// using separate storage backends for user and session data.
    ///
    /// # Arguments
    ///
    /// * `user_storage` - The storage implementation for user data
    /// * `session_storage` - The storage implementation for session data
    ///
    /// # Returns
    ///
    /// A new Torii instance with default managers using separate storage backends
    pub fn with_storages(user_storage: Arc<US>, session_storage: Arc<SS>) -> Self {
        let user_manager: Arc<dyn UserManager + Send + Sync> =
            Arc::new(DefaultUserManager::new(user_storage.clone()));
        let session_manager: Arc<dyn SessionManager + Send + Sync> =
            Arc::new(DefaultSessionManager::new(session_storage.clone()));
        let manager = PluginManager::new(user_storage.clone(), session_storage.clone());

        Self {
            user_storage,
            session_storage,
            user_manager,
            session_manager,
            manager,
            session_config: SessionConfig::default(),
        }
    }

    /// Create a new Torii instance with custom user and session managers
    ///
    /// This constructor allows full customization of the user and session managers.
    /// Note that storage instances are still needed for plugins to work properly.
    ///
    /// # Arguments
    ///
    /// * `user_storage` - The storage implementation for user data (used by plugins)
    /// * `session_storage` - The storage implementation for session data (used by plugins)
    /// * `user_manager` - The user manager implementation
    /// * `session_manager` - The session manager implementation
    ///
    /// # Returns
    ///
    /// A new Torii instance with the specified managers
    pub fn with_managers(
        user_storage: Arc<US>,
        session_storage: Arc<SS>,
        user_manager: Arc<dyn UserManager + Send + Sync>,
        session_manager: Arc<dyn SessionManager + Send + Sync>,
    ) -> Self {
        let manager = PluginManager::new(user_storage.clone(), session_storage.clone());

        Self {
            user_storage,
            session_storage,
            user_manager,
            session_manager,
            manager,
            session_config: SessionConfig::default(),
        }
    }

    /// Create a new Torii instance with custom managers only
    ///
    /// This constructor allows providing only custom managers without needing to
    /// provide the storage instances separately. The managers are responsible
    /// for encapsulating their own storage access.
    ///
    /// Note: Plugins will not work with this constructor since they need direct
    /// storage access.
    ///
    /// # Arguments
    ///
    /// * `user_manager` - The user manager implementation
    /// * `session_manager` - The session manager implementation
    ///
    /// # Returns
    ///
    /// A new Torii instance with the specified managers, but no plugin support
    pub fn with_custom_managers<UnitType>(
        user_manager: Arc<dyn UserManager + Send + Sync>,
        session_manager: Arc<dyn SessionManager + Send + Sync>,
    ) -> Torii<UnitType, UnitType>
    where
        UnitType: UserStorage + SessionStorage + Default + Clone + 'static,
    {
        // Create minimal storages just for type constraints
        let user_storage = Arc::new(UnitType::default());
        let session_storage = Arc::new(UnitType::default());
        let manager = PluginManager::new(user_storage.clone(), session_storage.clone());

        Torii {
            user_storage,
            session_storage,
            user_manager,
            session_manager,
            manager,
            session_config: SessionConfig::default(),
        }
    }

    /// Alternative constructor that uses the same storage for both users and sessions
    ///
    /// This constructor is a convenience method for situations where the same storage
    /// implementation is used for both user and session data.
    ///
    /// # Arguments
    ///
    /// * `storage` - The storage implementation for both user and session data
    /// * `user_manager` - The user manager implementation
    /// * `session_manager` - The session manager implementation
    ///
    /// # Returns
    ///
    /// A new Torii instance with the specified managers
    pub fn with_shared_storage<S>(
        storage: Arc<S>,
        user_manager: Arc<dyn UserManager + Send + Sync>,
        session_manager: Arc<dyn SessionManager + Send + Sync>,
    ) -> Torii<S, S>
    where
        S: UserStorage + SessionStorage + 'static,
    {
        let manager = PluginManager::new(storage.clone(), storage.clone());

        Torii {
            user_storage: storage.clone(),
            session_storage: storage,
            user_manager,
            session_manager,
            manager,
            session_config: SessionConfig::default(),
        }
    }

    /// Set the session configuration
    ///
    /// This method allows customization of session parameters such as
    /// expiration time and JWT settings.
    ///
    /// # Arguments
    ///
    /// * `config` - The session configuration to use
    pub fn with_session_config(mut self, config: SessionConfig) -> Self {
        self.session_config = config;
        self
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
        self.user_manager
            .get_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Create a new session for a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to create a session for
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the created session
    pub async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<Session, ToriiError> {
        let session = self
            .session_manager
            .create_session(
                user_id,
                user_agent,
                ip_address,
                self.session_config.expires_in,
            )
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        Ok(session)
    }

    /// Get a session by its token
    ///
    /// # Arguments
    ///
    /// * `session_id` - The token of the session to retrieve
    ///
    /// # Returns
    ///
    /// Returns the session if found and valid, otherwise returns an error
    pub async fn get_session(&self, session_id: &SessionToken) -> Result<Session, ToriiError> {
        let session = self
            .session_manager
            .get_session(session_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        Ok(session)
    }

    /// Delete a session by its ID
    ///
    /// # Arguments
    ///
    /// * `session_id`: The ID of the session to delete
    pub async fn delete_session(&self, session_id: &SessionToken) -> Result<(), ToriiError> {
        self.session_manager
            .delete_session(session_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Delete all sessions for a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to delete sessions for
    pub async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), ToriiError> {
        self.session_manager
            .delete_sessions_for_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }
}

#[cfg(feature = "password")]
impl<US, SS> Torii<US, SS>
where
    US: UserStorage + PasswordStorage + Clone + 'static,
    SS: SessionStorage + 'static,
{
    /// Add a password plugin to the Torii instance
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the password plugin registered
    pub fn with_password_plugin(mut self) -> Self {
        let user_manager = DefaultUserManager::new(self.user_storage.clone());
        let plugin = PasswordPlugin::new(Arc::new(user_manager), self.user_storage.clone());
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
            .get_plugin::<PasswordPlugin<DefaultUserManager<US>, US>>("password")
            .ok_or_else(|| ToriiError::PluginNotFound("password".to_string()))?;

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
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<PasswordPlugin<DefaultUserManager<US>, US>>("password")
            .ok_or_else(|| ToriiError::PluginNotFound("password".to_string()))?;

        let user = password_plugin
            .login_user_with_password(email, password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }

    /// Set a user's email as verified
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to set the email as verified
    pub async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), ToriiError> {
        self.user_manager
            .set_user_email_verified(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Delete a user and all associated data
    ///
    /// This operation permanently deletes the user and all related data, including sessions.
    /// This action cannot be undone.
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to delete
    ///
    /// # Returns
    ///
    /// Returns an empty result if the deletion was successful, or an error if it failed
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), ToriiError> {
        // First delete all sessions for the user
        self.delete_sessions_for_user(user_id).await?;

        // Then delete the user
        self.user_manager
            .delete_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Change a user's password and invalidate all existing sessions for the user.
    ///
    /// This method changes the user's password after verifying the old password
    /// is correct. For security reasons, it also invalidates all existing sessions
    /// for the user, requiring them to log in again with the new password.
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to change the password for
    /// * `old_password`: The current password for verification
    /// * `new_password`: The new password to set for the user
    pub async fn change_user_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<PasswordPlugin<DefaultUserManager<US>, US>>("password")
            .ok_or_else(|| ToriiError::PluginNotFound("password".to_string()))?;

        password_plugin
            .change_user_password(user_id, old_password, new_password)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        // Remove all existing sessions for the user.
        self.delete_sessions_for_user(user_id).await?;

        Ok(())
    }
}

#[cfg(feature = "oauth")]
use torii_core::storage::OAuthStorage;

#[cfg(feature = "oauth")]
impl<US, SS> Torii<US, SS>
where
    US: UserStorage + OAuthStorage + Clone + 'static,
    SS: SessionStorage + 'static,
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
        let user_manager = DefaultUserManager::new(self.user_storage.clone());
        let plugin = OAuthPlugin::new(provider, Arc::new(user_manager), self.user_storage.clone());
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
            .get_plugin::<OAuthPlugin<DefaultUserManager<US>, US>>(provider)
            .ok_or_else(|| ToriiError::PluginNotFound(provider.to_string()))?;

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
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let oauth_plugin = self
            .manager
            .get_plugin::<OAuthPlugin<DefaultUserManager<US>, US>>(provider)
            .ok_or_else(|| ToriiError::PluginNotFound(provider.to_string()))?;

        let (user, _) = oauth_plugin
            .exchange_code(code.to_string(), csrf_state.to_string())
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}

#[cfg(feature = "passkey")]
use torii_core::storage::PasskeyStorage;

#[cfg(feature = "passkey")]
impl<US, SS> Torii<US, SS>
where
    US: UserStorage + PasskeyStorage + Clone + 'static,
    SS: SessionStorage + 'static,
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
        let user_manager = DefaultUserManager::new(self.user_storage.clone());
        let plugin = PasskeyPlugin::new(
            rp_id,
            rp_origin,
            Arc::new(user_manager),
            self.user_storage.clone(),
        );
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
    /// Returns a [`PasskeyCredentialCreationOptions`] struct containing the challenge ID and WebAuthn options.
    pub async fn begin_passkey_registration(
        &self,
        email: &str,
    ) -> Result<PasskeyCredentialCreationOptions, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<DefaultUserManager<US>, US>>("passkey")
            .ok_or_else(|| ToriiError::PluginNotFound("passkey".to_string()))?;

        let request = PasskeyRegistrationRequest {
            email: email.to_string(),
        };

        <PasskeyPlugin<DefaultUserManager<US>, US> as PasskeyAuthPlugin>::start_registration(
            passkey_plugin.as_ref(),
            &request,
        )
        .await
        .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete a passkey registration
    ///
    /// # Arguments
    ///
    /// * `completion`: The registration completion data containing email, challenge ID, and response
    ///
    /// # Returns
    ///
    /// Returns the registered user if the registration is successful
    pub async fn complete_passkey_registration(
        &self,
        completion: &PasskeyRegistrationCompletion,
    ) -> Result<User, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<DefaultUserManager<US>, US>>("passkey")
            .ok_or_else(|| ToriiError::PluginNotFound("passkey".to_string()))?;

        <PasskeyPlugin<DefaultUserManager<US>, US> as PasskeyAuthPlugin>::complete_registration(
            passkey_plugin.as_ref(),
            completion,
        )
        .await
        .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Alternative complete passkey registration that accepts individual parameters
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to register
    /// * `challenge_id`: The challenge ID of the passkey
    /// * `challenge_response`: The challenge response of the passkey
    ///
    /// # Returns
    ///
    /// Returns the registered user if the registration is successful
    pub async fn complete_passkey_registration_with_params(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<User, ToriiError> {
        // Parse the challenge response
        let response = serde_json::from_value(challenge_response.clone()).map_err(|e| {
            ToriiError::AuthError(format!("Invalid challenge response format: {e}"))
        })?;

        let completion = PasskeyRegistrationCompletion {
            email: email.to_string(),
            challenge_id: ChallengeId::new(challenge_id.to_string()),
            response,
        };

        self.complete_passkey_registration(&completion).await
    }

    /// Begin a passkey login
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to login
    ///
    /// # Returns
    ///
    /// Returns a [`PasskeyCredentialRequestOptions`] struct containing the challenge ID and WebAuthn options.
    pub async fn begin_passkey_login(
        &self,
        email: &str,
    ) -> Result<PasskeyCredentialRequestOptions, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<DefaultUserManager<US>, US>>("passkey")
            .ok_or_else(|| ToriiError::PluginNotFound("passkey".to_string()))?;

        let request = PasskeyLoginRequest {
            email: email.to_string(),
        };

        <PasskeyPlugin<DefaultUserManager<US>, US> as PasskeyAuthPlugin>::start_login(
            passkey_plugin.as_ref(),
            &request,
        )
        .await
        .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete a passkey login
    ///
    /// # Arguments
    ///
    /// * `completion`: The login completion data containing email, challenge ID, and response
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if the login is successful
    pub async fn complete_passkey_login(
        &self,
        completion: &PasskeyLoginCompletion,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<DefaultUserManager<US>, US>>("passkey")
            .ok_or_else(|| ToriiError::PluginNotFound("passkey".to_string()))?;

        let user =
            <PasskeyPlugin<DefaultUserManager<US>, US> as PasskeyAuthPlugin>::complete_login(
                passkey_plugin.as_ref(),
                completion,
            )
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }

    /// Alternative complete passkey login that accepts individual parameters
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to login
    /// * `challenge_id`: The challenge ID of the passkey
    /// * `challenge_response`: The challenge response of the passkey
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if the login is successful
    pub async fn complete_passkey_login_with_params(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        // Parse the challenge response
        let response = serde_json::from_value(challenge_response.clone()).map_err(|e| {
            ToriiError::AuthError(format!("Invalid challenge response format: {e}"))
        })?;

        let completion = PasskeyLoginCompletion {
            email: email.to_string(),
            challenge_id: ChallengeId::new(challenge_id.to_string()),
            response,
        };

        self.complete_passkey_login(&completion, user_agent, ip_address)
            .await
    }
}

#[cfg(feature = "magic-link")]
use torii_core::storage::MagicLinkStorage;

#[cfg(feature = "magic-link")]
impl<US, SS> Torii<US, SS>
where
    US: UserStorage + MagicLinkStorage + Clone + 'static,
    SS: SessionStorage + 'static,
{
    /// Add a magic link plugin to the Torii instance
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the magic link plugin registered
    pub fn with_magic_link_plugin(mut self) -> Self {
        let user_manager = DefaultUserManager::new(self.user_storage.clone());
        let plugin = MagicLinkPlugin::new(Arc::new(user_manager), self.user_storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    /// Generate a magic token for email authentication
    ///
    /// This method generates a secure one-time use token for the given email and stores it.
    /// You can use this token to create a magic link to send to the user's email.
    ///
    /// # Arguments
    ///
    /// * `email` - The email of the user to generate the token for
    ///
    /// # Returns
    ///
    /// Returns the generated MagicToken if successful, which contains the token string
    /// that can be used to construct a magic link
    pub async fn generate_magic_token(&self, email: &str) -> Result<MagicToken, ToriiError> {
        let magic_link_plugin = self
            .manager
            .get_plugin::<MagicLinkPlugin<DefaultUserManager<US>, US>>("magic_link")
            .ok_or_else(|| ToriiError::PluginNotFound("magic_link".to_string()))?;

        let token = magic_link_plugin
            .generate_magic_token(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(token)
    }

    /// Verify a magic token and create a session
    ///
    /// This method validates the provided token, marks it as used, and creates a new session
    /// for the associated user if the token is valid.
    ///
    /// # Arguments
    ///
    /// * `token` - The magic token string to verify
    /// * `user_agent` - Optional user agent information for the session
    /// * `ip_address` - Optional IP address information for the session
    ///
    /// # Returns
    ///
    /// Returns the user and a new session if the token is valid and not expired
    pub async fn verify_magic_token(
        &self,
        token: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let magic_link_plugin = self
            .manager
            .get_plugin::<MagicLinkPlugin<DefaultUserManager<US>, US>>("magic_link")
            .ok_or_else(|| ToriiError::PluginNotFound("magic_link".to_string()))?;

        let user = magic_link_plugin
            .verify_magic_token(token)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}
