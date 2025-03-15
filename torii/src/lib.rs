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
//! let storage = Arc::new(SqliteStorage::connect("sqlite::memory:").await.unwrap());
//!
//!     let torii = Torii::new(storage.clone(), storage.clone())
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
    PluginManager, SessionStorage,
    session::{DefaultSessionManager, JwtConfig, JwtSessionManager, SessionManager},
    storage::{MagicLinkStorage, OAuthStorage, PasskeyStorage, PasswordStorage, UserStorage},
};

/// Re-export core types from torii_core
///
/// These types are commonly used when working with the Torii API.
pub use torii_core::{
    session::{Session, SessionToken},
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
pub use torii_auth_passkey::{PasskeyChallenge, PasskeyPlugin};

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
/// - `U`: The user storage implementation
/// - `S`: The session storage implementation
/// - `M`: The session manager implementation
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
pub struct Torii<U, S, M = DefaultSessionManager<S>>
where
    U: UserStorage,
    S: SessionStorage,
    M: SessionManager + 'static,
{
    user_storage: Arc<U>,
    session_storage: Arc<S>,
    session_manager: Arc<M>,
    manager: PluginManager<U, S>,
    session_config: SessionConfig,
}

impl<U, S> Torii<U, S, DefaultSessionManager<S>>
where
    U: UserStorage,
    S: SessionStorage,
{
    /// Create a new Torii instance with the given user and session storage
    ///
    /// This constructor initializes Torii with a default session manager that uses
    /// the provided session storage for tracking user sessions.
    ///
    /// # Arguments
    ///
    /// * `user_storage` - The storage implementation for user data
    /// * `session_storage` - The storage implementation for session data
    ///
    /// # Returns
    ///
    /// A new Torii instance with the default session manager
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        let session_manager = Arc::new(DefaultSessionManager::new(session_storage.clone()));
        let manager = PluginManager::new(user_storage.clone(), session_storage.clone());

        Self {
            user_storage,
            session_storage,
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
    pub fn with_jwt_sessions(self, jwt_config: JwtConfig) -> Torii<U, S, JwtSessionManager> {
        let session_manager = Arc::new(JwtSessionManager::new(jwt_config.clone()));
        let manager = PluginManager::new(self.user_storage.clone(), self.session_storage.clone());

        Torii {
            user_storage: self.user_storage,
            session_storage: self.session_storage,
            session_manager,
            manager,
            session_config: self.session_config.with_jwt(jwt_config),
        }
    }
}

impl<U, S, M> Torii<U, S, M>
where
    U: UserStorage,
    S: SessionStorage,
    M: SessionManager + 'static,
{
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
        let user = self
            .user_storage
            .get_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        Ok(user)
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
impl<U, S, M> Torii<U, S, M>
where
    U: PasswordStorage + Clone,
    S: SessionStorage + Clone,
    M: SessionManager + 'static,
{
    /// Add a password plugin to the Torii instance
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the password plugin registered
    pub fn with_password_plugin(mut self) -> Self {
        let plugin = PasswordPlugin::new(self.user_storage.clone());
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
            .get_plugin::<PasswordPlugin<U>>("password")
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
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<PasswordPlugin<U>>("password")
            .ok_or(ToriiError::PluginNotFound("password".to_string()))?;

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
        self.user_storage
            .set_user_email_verified(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }
}

#[cfg(feature = "oauth")]
impl<U, S, M> Torii<U, S, M>
where
    U: OAuthStorage + Clone,
    S: SessionStorage + Clone,
    M: SessionManager + 'static,
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
        let plugin = OAuthPlugin::new(provider, self.user_storage.clone());
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
            .get_plugin::<OAuthPlugin<U>>(provider)
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
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let oauth_plugin = self
            .manager
            .get_plugin::<OAuthPlugin<U>>(provider)
            .ok_or(ToriiError::PluginNotFound(provider.to_string()))?;

        let user = oauth_plugin
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
impl<U, S, M> Torii<U, S, M>
where
    U: PasskeyStorage + Clone,
    S: SessionStorage + Clone,
    M: SessionManager + 'static,
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
        let plugin = PasskeyPlugin::new(rp_id, rp_origin, self.user_storage.clone());
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
            .get_plugin::<PasskeyPlugin<U>>("passkey")
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
    ) -> Result<User, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let user = passkey_plugin
            .complete_registration(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(user)
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
            .get_plugin::<PasskeyPlugin<U>>("passkey")
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
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let user = passkey_plugin
            .complete_login(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}

#[cfg(feature = "magic-link")]
impl<U, S, M> Torii<U, S, M>
where
    U: MagicLinkStorage + Clone,
    S: SessionStorage + Clone,
    M: SessionManager + 'static,
{
    /// Add a magic link plugin to the Torii instance
    ///
    /// # Returns
    ///
    /// Returns the updated Torii instance with the magic link plugin registered
    pub fn with_magic_link_plugin(mut self) -> Self {
        let plugin = MagicLinkPlugin::new(self.user_storage.clone());
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
            .get_plugin::<MagicLinkPlugin<U>>("magic_link")
            .ok_or(ToriiError::PluginNotFound("magic_link".to_string()))?;

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
            .get_plugin::<MagicLinkPlugin<U>>("magic_link")
            .ok_or(ToriiError::PluginNotFound("magic_link".to_string()))?;

        let user = magic_link_plugin
            .verify_magic_token(token)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let user = self
            .user_storage
            .get_user(&user.user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        if let Some(user) = user {
            let session = self
                .create_session(&user.id, user_agent, ip_address)
                .await?;
            Ok((user, session))
        } else {
            Err(ToriiError::AuthError("User not found".to_string()))
        }
    }
}
