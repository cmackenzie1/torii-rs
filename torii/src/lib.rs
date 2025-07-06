//! # Torii
//!
//! Torii is a powerful authentication framework for Rust applications that gives you complete control
//! over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user
//! information in their cloud, Torii lets you own and manage your authentication stack while providing
//! modern auth features through a flexible service architecture.
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
//! use torii_storage_sqlite::SqliteRepositoryProvider;
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() {
//!     let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
//!     let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
//!
//!     let torii = Torii::new(repositories);
//! }
//! ```
use std::sync::Arc;

use chrono::Duration;
use torii_core::{
    JwtSessionProvider, OpaqueSessionProvider, RepositoryProvider, SessionProvider,
    repositories::{PasswordRepositoryAdapter, SessionRepositoryAdapter, UserRepositoryAdapter},
    services::{SessionService, UserService},
};

#[cfg(feature = "oauth")]
use torii_core::repositories::OAuthRepositoryAdapter;

#[cfg(feature = "passkey")]
use torii_core::repositories::PasskeyRepositoryAdapter;

#[cfg(feature = "magic-link")]
use torii_core::repositories::MagicLinkRepositoryAdapter;

#[cfg(feature = "password")]
use torii_core::services::PasswordService;

#[cfg(feature = "oauth")]
use torii_core::services::OAuthService;

#[cfg(feature = "passkey")]
use torii_core::services::PasskeyService;

#[cfg(feature = "magic-link")]
use torii_core::services::MagicLinkService;

/// Re-export core types from torii_core
///
/// These types are commonly used when working with the Torii API.
pub use torii_core::{
    JwtAlgorithm, JwtClaims, JwtConfig, JwtMetadata, Session, SessionToken, User, UserId,
};

/// Re-export storage types
pub use torii_core::storage::MagicToken;

// Note: Authentication is now handled by services rather than plugins
// The old plugin system has been replaced with a service-based architecture

/// Re-export storage backends
///
/// These storage implementations are available when the corresponding feature is enabled.
#[cfg(feature = "sqlite")]
pub use torii_storage_sqlite::{SqliteRepositoryProvider, SqliteStorage};

#[cfg(feature = "postgres")]
pub use torii_storage_postgres::PostgresStorage;
// TODO: Add PostgresRepositoryProvider once implemented

#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
pub use torii_storage_seaorm::{SeaORMStorage, repositories::SeaORMRepositoryProvider};

/// Errors that can occur when using Torii.
///
/// This enum represents the various error types that can occur when using the Torii authentication framework.
#[derive(Debug, thiserror::Error)]
pub enum ToriiError {
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
/// It includes settings for session expiration and the session provider type.
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
    /// Session provider type
    pub provider_type: SessionProviderType,
}

/// Type of session provider to use
pub enum SessionProviderType {
    /// Use opaque tokens stored in database
    Opaque,
    /// Use self-contained JWT tokens
    Jwt(JwtConfig),
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::days(30),
            provider_type: SessionProviderType::Opaque,
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
        self.provider_type = SessionProviderType::Jwt(jwt_config);
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

/// The main authentication coordinator that manages services and storage.
///
/// `Torii` acts as the central point for configuring and managing authentication in your application.
/// It coordinates between different authentication services and provides access to user/session storage.
///
/// # Example
///
/// ```rust,no_run
/// use torii::{Torii, UserId};
/// use torii_storage_sqlite::SqliteRepositoryProvider;
/// use std::sync::Arc;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
///     let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
///
///     // Create a new Torii instance with the repository provider
///     let torii = Torii::new(repositories);
///
///     // Use torii to manage authentication
///     let user_id = UserId::new("example-user-id");
///     let user = torii.get_user(&user_id).await?;
///     println!("User: {:?}", user);
///     
///     Ok(())
/// }
/// ```
pub struct Torii<R: RepositoryProvider> {
    repositories: Arc<R>,
    user_service: Arc<UserService<UserRepositoryAdapter<R>>>,
    session_service: Arc<SessionService<Box<dyn SessionProvider>>>,
    session_provider: Arc<Box<dyn SessionProvider>>,

    #[cfg(feature = "password")]
    password_service: Arc<PasswordService<UserRepositoryAdapter<R>, PasswordRepositoryAdapter<R>>>,

    #[cfg(feature = "oauth")]
    #[allow(dead_code)] // TODO: Expose OAuth service methods in Torii API
    oauth_service: Arc<OAuthService<UserRepositoryAdapter<R>, OAuthRepositoryAdapter<R>>>,

    #[cfg(feature = "passkey")]
    #[allow(dead_code)] // TODO: Expose passkey service methods in Torii API
    passkey_service: Arc<PasskeyService<UserRepositoryAdapter<R>, PasskeyRepositoryAdapter<R>>>,

    #[cfg(feature = "magic-link")]
    #[allow(dead_code)] // TODO: Expose magic link service methods in Torii API
    magic_link_service:
        Arc<MagicLinkService<UserRepositoryAdapter<R>, MagicLinkRepositoryAdapter<R>>>,

    session_config: SessionConfig,
}

impl<R: RepositoryProvider> Torii<R> {
    /// Create a new Torii instance with a repository provider
    ///
    /// This constructor initializes Torii with all the required services
    /// using the provided repository provider.
    ///
    /// # Arguments
    ///
    /// * `repositories` - The repository provider implementation
    ///
    /// # Returns
    ///
    /// A new Torii instance with all services configured
    pub fn new(repositories: Arc<R>) -> Self {
        // Create repository adapters
        let user_repo = Arc::new(UserRepositoryAdapter::new(repositories.clone()));
        let session_repo = Arc::new(SessionRepositoryAdapter::new(repositories.clone()));

        let user_service = Arc::new(UserService::new(user_repo.clone()));

        // Default to opaque session provider
        let session_provider: Arc<Box<dyn SessionProvider>> =
            Arc::new(Box::new(OpaqueSessionProvider::new(session_repo)));
        let session_service = Arc::new(SessionService::new(session_provider.clone()));

        Self {
            repositories: repositories.clone(),
            user_service,
            session_service,
            session_provider,

            #[cfg(feature = "password")]
            password_service: Arc::new(PasswordService::new(
                user_repo.clone(),
                Arc::new(PasswordRepositoryAdapter::new(repositories.clone())),
            )),

            #[cfg(feature = "oauth")]
            oauth_service: Arc::new(OAuthService::new(
                user_repo.clone(),
                Arc::new(torii_core::repositories::OAuthRepositoryAdapter::new(
                    repositories.clone(),
                )),
            )),

            #[cfg(feature = "passkey")]
            passkey_service: Arc::new(PasskeyService::new(
                user_repo.clone(),
                Arc::new(torii_core::repositories::PasskeyRepositoryAdapter::new(
                    repositories.clone(),
                )),
            )),

            #[cfg(feature = "magic-link")]
            magic_link_service: Arc::new(MagicLinkService::new(
                user_repo,
                Arc::new(torii_core::repositories::MagicLinkRepositoryAdapter::new(
                    repositories.clone(),
                )),
            )),

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
        // Create the appropriate session provider based on config
        let session_provider: Arc<Box<dyn SessionProvider>> = match &config.provider_type {
            SessionProviderType::Opaque => {
                let session_repo =
                    Arc::new(SessionRepositoryAdapter::new(self.repositories.clone()));
                Arc::new(Box::new(OpaqueSessionProvider::new(session_repo)))
            }
            SessionProviderType::Jwt(jwt_config) => {
                Arc::new(Box::new(JwtSessionProvider::new(jwt_config.clone())))
            }
        };

        self.session_provider = session_provider.clone();
        self.session_service = Arc::new(SessionService::new(session_provider));
        self.session_config = config;
        self
    }

    /// Configure JWT sessions
    ///
    /// This is a convenience method for setting up JWT session configuration.
    ///
    /// # Arguments
    ///
    /// * `jwt_config` - The JWT configuration to use
    pub fn with_jwt_sessions(self, jwt_config: JwtConfig) -> Self {
        let config = SessionConfig::default().with_jwt(jwt_config);
        self.with_session_config(config)
    }

    /// Run migrations for all repositories
    pub async fn migrate(&self) -> Result<(), ToriiError> {
        self.repositories
            .migrate()
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Health check for all repositories
    pub async fn health_check(&self) -> Result<(), ToriiError> {
        self.repositories
            .health_check()
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
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
        self.user_service
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
        self.session_service
            .create_session(
                user_id,
                user_agent,
                ip_address,
                self.session_config.expires_in,
            )
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
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
        self.session_service
            .get_session(session_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?
            .ok_or(ToriiError::StorageError("Session not found".to_string()))
    }

    /// Delete a session by its ID
    ///
    /// # Arguments
    ///
    /// * `session_id`: The ID of the session to delete
    pub async fn delete_session(&self, session_id: &SessionToken) -> Result<(), ToriiError> {
        self.session_service
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
        self.session_service
            .delete_user_sessions(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Mark a user's email as verified
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to mark as verified
    pub async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), ToriiError> {
        self.user_service
            .verify_email(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }

    /// Delete a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to delete
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), ToriiError> {
        self.user_service
            .delete_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))
    }
}

#[cfg(feature = "password")]
impl<R: RepositoryProvider> Torii<R> {
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
        self.password_service
            .register_user(email, password, None)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
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
        let user = self
            .password_service
            .authenticate(email, password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
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
        self.password_service
            .change_password(user_id, old_password, new_password)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        // Remove all existing sessions for the user.
        self.delete_sessions_for_user(user_id).await?;

        Ok(())
    }
}

#[cfg(feature = "magic-link")]
impl<R: RepositoryProvider> Torii<R> {
    /// Generate a magic token for a user
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to generate a token for
    ///
    /// # Returns
    ///
    /// Returns the generated magic token
    pub async fn generate_magic_token(&self, email: &str) -> Result<MagicToken, ToriiError> {
        self.magic_link_service
            .generate_token(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Verify a magic token and return the user and session
    ///
    /// # Arguments
    ///
    /// * `token`: The magic token to verify
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if the token is valid
    pub async fn verify_magic_token(
        &self,
        token: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let user = self
            .magic_link_service
            .verify_token(token)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?
            .ok_or_else(|| ToriiError::AuthError("Invalid magic token".to_string()))?;

        let session = self
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}
