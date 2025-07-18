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
//! use torii::sqlite::SqliteRepositoryProvider;
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
    repositories::{
        PasswordRepositoryAdapter, SessionRepositoryAdapter, TokenRepositoryAdapter,
        UserRepositoryAdapter,
    },
    services::{SessionService, UserService},
};

#[cfg(feature = "oauth")]
use torii_core::repositories::OAuthRepositoryAdapter;

#[cfg(feature = "passkey")]
use torii_core::repositories::PasskeyRepositoryAdapter;

#[cfg(feature = "password")]
use torii_core::services::PasswordService;

#[cfg(feature = "oauth")]
use torii_core::services::OAuthService;

#[cfg(feature = "passkey")]
use torii_core::services::PasskeyService;

#[cfg(feature = "magic-link")]
use torii_core::services::MagicLinkService;

#[cfg(any(feature = "password", feature = "magic-link"))]
pub use torii_core::services::PasswordResetService;

#[cfg(feature = "mailer")]
use torii_core::services::{MailerService, ToriiMailerService};

/// Re-export core types from torii_core
///
/// These types are commonly used when working with the Torii API.
pub use torii_core::{
    JwtAlgorithm, JwtClaims, JwtConfig, JwtMetadata, Session, SessionToken, User, UserId,
};

/// Re-export storage types
pub use torii_core::storage::{SecureToken, TokenPurpose};

/// Re-export mailer types when mailer feature is enabled
#[cfg(feature = "mailer")]
pub use torii_mailer::{MailerConfig, TemplateContext};

// Note: Authentication is now handled by services rather than plugins
// The old plugin system has been replaced with a service-based architecture

/// Namespaced authentication providers for clean API organization
///
/// These structs provide focused interfaces for specific authentication methods
/// while maintaining access to the underlying Torii functionality.
/// Password-based authentication provider
///
/// Provides methods for password registration, login, password changes, and password resets.
#[cfg(feature = "password")]
pub struct PasswordAuth<'a, R: RepositoryProvider> {
    torii: &'a Torii<R>,
}

/// Magic link authentication provider
///
/// Provides methods for generating and verifying magic link tokens.
#[cfg(feature = "magic-link")]
pub struct MagicLinkAuth<'a, R: RepositoryProvider> {
    torii: &'a Torii<R>,
}

/// OAuth authentication provider
///
/// Provides methods for OAuth flows and account linking.
#[cfg(feature = "oauth")]
pub struct OAuthAuth<'a, R: RepositoryProvider> {
    torii: &'a Torii<R>,
}

/// Passkey authentication provider
///
/// Provides methods for WebAuthn/passkey registration and authentication.
#[cfg(feature = "passkey")]
pub struct PasskeyAuth<'a, R: RepositoryProvider> {
    torii: &'a Torii<R>,
}

// Re-export storage backends
// These storage implementations are available when the corresponding feature is enabled.

/// SQLite storage backend
#[cfg(feature = "sqlite")]
pub mod sqlite {
    pub use torii_storage_sqlite::{SqliteRepositoryProvider, SqliteStorage};
}

/// PostgreSQL storage backend
#[cfg(feature = "postgres")]
pub mod postgres {
    pub use torii_storage_postgres::PostgresStorage;
    // TODO: Add PostgresRepositoryProvider once implemented
}

/// SeaORM storage backend
#[cfg(any(
    feature = "seaorm-sqlite",
    feature = "seaorm-postgres",
    feature = "seaorm-mysql",
    feature = "seaorm"
))]
pub mod seaorm {
    pub use torii_storage_seaorm::{SeaORMStorage, repositories::SeaORMRepositoryProvider};
}

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
/// use torii::sqlite::SqliteRepositoryProvider;
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
    magic_link_service: Arc<MagicLinkService<UserRepositoryAdapter<R>, TokenRepositoryAdapter<R>>>,

    #[cfg(any(feature = "password", feature = "magic-link"))]
    password_reset_service: Arc<
        PasswordResetService<
            UserRepositoryAdapter<R>,
            PasswordRepositoryAdapter<R>,
            TokenRepositoryAdapter<R>,
        >,
    >,

    #[cfg(feature = "mailer")]
    mailer_service: Option<Arc<ToriiMailerService>>,

    session_config: SessionConfig,
}

// Namespace accessor methods
impl<R: RepositoryProvider> Torii<R> {
    /// Access password-based authentication methods
    #[cfg(feature = "password")]
    pub fn password(&self) -> PasswordAuth<R> {
        PasswordAuth { torii: self }
    }

    /// Access magic link authentication methods
    #[cfg(feature = "magic-link")]
    pub fn magic_link(&self) -> MagicLinkAuth<R> {
        MagicLinkAuth { torii: self }
    }

    /// Access OAuth authentication methods
    #[cfg(feature = "oauth")]
    pub fn oauth(&self) -> OAuthAuth<R> {
        OAuthAuth { torii: self }
    }

    /// Access passkey authentication methods
    #[cfg(feature = "passkey")]
    pub fn passkey(&self) -> PasskeyAuth<R> {
        PasskeyAuth { torii: self }
    }
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
                user_repo.clone(),
                Arc::new(torii_core::repositories::TokenRepositoryAdapter::new(
                    repositories.clone(),
                )),
            )),

            #[cfg(any(feature = "password", feature = "magic-link"))]
            password_reset_service: Arc::new(PasswordResetService::new(
                user_repo,
                Arc::new(PasswordRepositoryAdapter::new(repositories.clone())),
                Arc::new(torii_core::repositories::TokenRepositoryAdapter::new(
                    repositories.clone(),
                )),
            )),

            #[cfg(feature = "mailer")]
            mailer_service: None,

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

    /// Configure the mailer service
    ///
    /// This method allows you to add email functionality to Torii for sending
    /// authentication-related emails like magic links, welcome emails, and password reset notifications.
    ///
    /// # Arguments
    ///
    /// * `mailer_config` - The mailer configuration to use
    ///
    /// # Returns
    ///
    /// Returns a Result with the updated Torii instance or an error if the mailer configuration is invalid
    #[cfg(feature = "mailer")]
    pub fn with_mailer(mut self, mailer_config: MailerConfig) -> Result<Self, ToriiError> {
        let mailer = ToriiMailerService::new(mailer_config)
            .map_err(|e| ToriiError::StorageError(format!("Failed to configure mailer: {e}")))?;
        self.mailer_service = Some(Arc::new(mailer));
        Ok(self)
    }

    /// Configure the mailer service from environment variables
    ///
    /// This is a convenience method that reads mailer configuration from environment variables.
    ///
    /// # Returns
    ///
    /// Returns a Result with the updated Torii instance or an error if the environment configuration is invalid
    #[cfg(feature = "mailer")]
    pub fn with_mailer_from_env(mut self) -> Result<Self, ToriiError> {
        let mailer = ToriiMailerService::from_env().map_err(|e| {
            ToriiError::StorageError(format!("Failed to configure mailer from environment: {e}"))
        })?;
        self.mailer_service = Some(Arc::new(mailer));
        Ok(self)
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

// Password authentication implementation moved to PasswordAuth namespace

// Password reset methods moved to PasswordAuth namespace

/// Implementation of password-based authentication methods
#[cfg(feature = "password")]
impl<R: RepositoryProvider> PasswordAuth<'_, R> {
    /// Get reference to the underlying Torii instance
    fn torii(&self) -> &Torii<R> {
        self.torii
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
    pub async fn register(&self, email: &str, password: &str) -> Result<User, ToriiError> {
        self.register_with_name(email, password, None).await
    }

    /// Register a user with a password and optional name
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to register
    /// * `password`: The password of the user to register
    /// * `name`: Optional name for the user
    ///
    /// # Returns
    ///
    /// Returns the registered user
    pub async fn register_with_name(
        &self,
        email: &str,
        password: &str,
        name: Option<&str>,
    ) -> Result<User, ToriiError> {
        let torii = self.torii();
        let user = torii
            .password_service
            .register_user(email, password, name.map(|n| n.to_string()))
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        // Send welcome email if mailer is configured
        #[cfg(feature = "mailer")]
        if let Some(mailer) = &torii.mailer_service {
            let user_name = user.name.as_deref();
            if let Err(e) = mailer.send_welcome_email(&user.email, user_name).await {
                tracing::warn!("Failed to send welcome email: {}", e);
                // Don't fail the registration if email sending fails
            }
        }

        Ok(user)
    }

    /// Authenticate a user with email and password
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to authenticate
    /// * `password`: The password of the user to authenticate
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if authentication is successful
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let torii = self.torii();
        let user = torii
            .password_service
            .authenticate(email, password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        let session = torii
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }

    /// Change a user's password and invalidate all existing sessions
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
    pub async fn change_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), ToriiError> {
        let torii = self.torii();
        // Get user details before changing password for potential email notification
        let user = torii
            .get_user(user_id)
            .await?
            .ok_or_else(|| ToriiError::AuthError("User not found".to_string()))?;

        torii
            .password_service
            .change_password(user_id, old_password, new_password)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;

        // Remove all existing sessions for the user
        torii.delete_sessions_for_user(user_id).await?;

        // Send password changed notification email if mailer is configured
        #[cfg(feature = "mailer")]
        if let Some(mailer) = &torii.mailer_service {
            let user_name = user.name.as_deref();
            if let Err(e) = mailer
                .send_password_changed_email(&user.email, user_name)
                .await
            {
                tracing::warn!("Failed to send password changed email: {}", e);
                // Don't fail the password change if email sending fails
            }
        }

        Ok(())
    }

    /// Request a password reset for the given email address
    ///
    /// This will generate a secure reset token and send a password reset email if mailer is configured.
    /// For security reasons, this method doesn't reveal whether the email exists or not.
    ///
    /// # Arguments
    ///
    /// * `email`: The email address to send the password reset to
    /// * `reset_url_base`: The base URL for the password reset form (e.g., "https://yourapp.com/reset")
    ///
    /// # Returns
    ///
    /// Always returns Ok() to prevent email enumeration attacks
    #[cfg(any(feature = "password", feature = "magic-link"))]
    pub async fn reset_password_initiate(
        &self,
        email: &str,
        reset_url_base: &str,
    ) -> Result<(), ToriiError> {
        let torii = self.torii();
        let result = torii
            .password_reset_service
            .request_password_reset(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        // Send password reset email if mailer is configured and user exists
        #[cfg(feature = "mailer")]
        if let Some((user, token)) = result {
            if let Some(mailer) = &torii.mailer_service {
                let reset_link = format!("{}/{}", reset_url_base.trim_end_matches('/'), token);
                if let Err(e) = mailer
                    .send_password_reset_email(&user.email, &reset_link, user.name.as_deref())
                    .await
                {
                    tracing::warn!("Failed to send password reset email: {}", e);
                    // Don't fail the password reset request if email sending fails
                }
            }
        }

        // Always return Ok() to prevent email enumeration attacks
        Ok(())
    }

    /// Request a password reset with custom expiration time
    ///
    /// # Arguments
    ///
    /// * `email`: The email address to send the password reset to
    /// * `reset_url_base`: The base URL for the password reset form
    /// * `expires_in`: How long the reset token should be valid
    #[cfg(any(feature = "password", feature = "magic-link"))]
    pub async fn reset_password_initiate_with_expiration(
        &self,
        email: &str,
        reset_url_base: &str,
        expires_in: Duration,
    ) -> Result<(), ToriiError> {
        let torii = self.torii();
        let result = torii
            .password_reset_service
            .request_password_reset_with_expiration(email, expires_in)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        // Send password reset email if mailer is configured and user exists
        #[cfg(feature = "mailer")]
        if let Some((user, token)) = result {
            if let Some(mailer) = &torii.mailer_service {
                let reset_link = format!("{}/{}", reset_url_base.trim_end_matches('/'), token);
                if let Err(e) = mailer
                    .send_password_reset_email(&user.email, &reset_link, user.name.as_deref())
                    .await
                {
                    tracing::warn!("Failed to send password reset email: {}", e);
                    // Don't fail the password reset request if email sending fails
                }
            }
        }

        // Always return Ok() to prevent email enumeration attacks
        Ok(())
    }

    /// Verify a password reset token without consuming it
    ///
    /// This is useful for frontend validation before showing the password reset form.
    ///
    /// # Arguments
    ///
    /// * `token`: The reset token to verify
    ///
    /// # Returns
    ///
    /// Returns true if the token is valid and not expired
    #[cfg(any(feature = "password", feature = "magic-link"))]
    pub async fn reset_password_verify_token(&self, token: &str) -> Result<bool, ToriiError> {
        self.torii()
            .password_reset_service
            .verify_reset_token(token)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete the password reset process and invalidate all user sessions
    ///
    /// This will:
    /// 1. Verify and consume the reset token
    /// 2. Update the user's password
    /// 3. Invalidate all existing sessions for security
    /// 4. Send a password changed notification email if mailer is configured
    ///
    /// # Arguments
    ///
    /// * `token`: The reset token received via email
    /// * `new_password`: The new password to set
    ///
    /// # Returns
    ///
    /// Returns the user whose password was reset
    #[cfg(any(feature = "password", feature = "magic-link"))]
    pub async fn reset_password_complete(
        &self,
        token: &str,
        new_password: &str,
    ) -> Result<User, ToriiError> {
        let torii = self.torii();
        let user = torii
            .password_reset_service
            .reset_password(token, new_password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        // Invalidate all existing sessions for security
        torii.delete_sessions_for_user(&user.id).await?;

        // Send password changed notification email if mailer is configured
        #[cfg(feature = "mailer")]
        if let Some(mailer) = &torii.mailer_service {
            let user_name = user.name.as_deref();
            if let Err(e) = mailer
                .send_password_changed_email(&user.email, user_name)
                .await
            {
                tracing::warn!("Failed to send password changed email: {}", e);
                // Don't fail the password reset if email sending fails
            }
        }

        Ok(user)
    }
}

/// Implementation of magic link authentication methods
#[cfg(feature = "magic-link")]
impl<R: RepositoryProvider> MagicLinkAuth<'_, R> {
    /// Get reference to the underlying Torii instance
    fn torii(&self) -> &Torii<R> {
        self.torii
    }

    /// Generate a magic token for a user
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to generate a token for
    ///
    /// # Returns
    ///
    /// Returns the generated magic token
    pub async fn generate_token(&self, email: &str) -> Result<SecureToken, ToriiError> {
        let torii = self.torii();
        torii
            .magic_link_service
            .generate_token(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Send a magic link via email
    ///
    /// # Arguments
    ///
    /// * `email`: The email of the user to send the magic link to
    /// * `magic_link_url_base`: The base URL for the magic link (e.g., "https://yourapp.com/auth/magic")
    ///
    /// # Returns
    ///
    /// Returns the generated magic token
    pub async fn send_link(
        &self,
        email: &str,
        magic_link_url_base: &str,
    ) -> Result<SecureToken, ToriiError> {
        let token = self.generate_token(email).await?;
        let torii = self.torii();

        // Send magic link email if mailer is configured
        #[cfg(feature = "mailer")]
        if let Some(mailer) = &torii.mailer_service {
            let magic_link = format!(
                "{}/{}",
                magic_link_url_base.trim_end_matches('/'),
                token.token
            );

            // Get user name if the user exists
            let user = torii
                .user_service
                .get_user_by_email(email)
                .await
                .ok()
                .flatten();
            let user_name = user.as_ref().and_then(|u| u.name.as_deref());

            if let Err(e) = mailer
                .send_magic_link_email(email, &magic_link, user_name)
                .await
            {
                tracing::warn!("Failed to send magic link email: {}", e);
                // Don't fail the token generation if email sending fails
            }
        }

        Ok(token)
    }

    /// Authenticate a user with a magic link token
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
    pub async fn authenticate(
        &self,
        token: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let torii = self.torii();
        let user = torii
            .magic_link_service
            .verify_token(token)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?
            .ok_or_else(|| ToriiError::AuthError("Invalid magic token".to_string()))?;

        let session = torii
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}

/// Implementation of OAuth authentication methods
#[cfg(feature = "oauth")]
impl<R: RepositoryProvider> OAuthAuth<'_, R> {
    /// Get reference to the underlying Torii instance
    fn torii(&self) -> &Torii<R> {
        self.torii
    }

    /// Create or get a user from OAuth provider information
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider name (e.g., "google", "github")
    /// * `subject`: The user's ID from the OAuth provider
    /// * `email`: The user's email address from the OAuth provider
    /// * `name`: Optional display name from the OAuth provider
    ///
    /// # Returns
    ///
    /// Returns the user (either existing or newly created)
    pub async fn get_or_create_user(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
        name: Option<String>,
    ) -> Result<User, ToriiError> {
        let torii = self.torii();
        torii
            .oauth_service
            .get_or_create_user(provider, subject, email, name)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Link an existing user to an OAuth account
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to link
    /// * `provider`: The OAuth provider name
    /// * `subject`: The user's ID from the OAuth provider
    ///
    /// # Returns
    ///
    /// Returns Ok() if linking succeeds, or an error if the account is already linked
    pub async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), ToriiError> {
        let torii = self.torii();
        torii
            .oauth_service
            .link_account(user_id, provider, subject)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Get OAuth account information
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider name
    /// * `subject`: The user's ID from the OAuth provider
    ///
    /// # Returns
    ///
    /// Returns the OAuth account if found
    pub async fn get_account(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<torii_core::OAuthAccount>, ToriiError> {
        let torii = self.torii();
        torii
            .oauth_service
            .get_account(provider, subject)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Store a PKCE verifier for OAuth flows
    ///
    /// # Arguments
    ///
    /// * `csrf_state`: The CSRF state token
    /// * `pkce_verifier`: The PKCE verifier string
    /// * `expires_in`: How long the verifier should be valid
    ///
    /// # Returns
    ///
    /// Returns Ok() if the verifier is stored successfully
    pub async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), ToriiError> {
        let torii = self.torii();
        torii
            .oauth_service
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Get and consume a PKCE verifier (one-time use)
    ///
    /// # Arguments
    ///
    /// * `csrf_state`: The CSRF state token
    ///
    /// # Returns
    ///
    /// Returns the PKCE verifier if found and valid
    pub async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, ToriiError> {
        let torii = self.torii();
        torii
            .oauth_service
            .get_pkce_verifier(csrf_state)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Complete OAuth authentication flow and create session
    ///
    /// # Arguments
    ///
    /// * `provider`: The OAuth provider name
    /// * `subject`: The user's ID from the OAuth provider
    /// * `email`: The user's email address from the OAuth provider
    /// * `name`: Optional display name from the OAuth provider
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if authentication succeeds
    pub async fn authenticate(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
        name: Option<String>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let user = self
            .get_or_create_user(provider, subject, email, name)
            .await?;

        let torii = self.torii();
        let session = torii
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }
}

/// Implementation of Passkey authentication methods
#[cfg(feature = "passkey")]
impl<R: RepositoryProvider> PasskeyAuth<'_, R> {
    /// Get reference to the underlying Torii instance
    fn torii(&self) -> &Torii<R> {
        self.torii
    }

    /// Register a new passkey credential for a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to register the credential for
    /// * `credential_id`: The credential ID from the WebAuthn response
    /// * `public_key`: The public key from the WebAuthn response
    /// * `name`: Optional name for the credential (e.g., "iPhone", "YubiKey")
    ///
    /// # Returns
    ///
    /// Returns the registered passkey credential
    pub async fn register_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<torii_core::repositories::PasskeyCredential, ToriiError> {
        let torii = self.torii();
        torii
            .passkey_service
            .register_credential(user_id, credential_id, public_key, name)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Get all passkey credentials for a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to get credentials for
    ///
    /// # Returns
    ///
    /// Returns a list of passkey credentials for the user
    pub async fn get_user_credentials(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<torii_core::repositories::PasskeyCredential>, ToriiError> {
        let torii = self.torii();
        torii
            .passkey_service
            .get_user_credentials(user_id)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Get a specific passkey credential
    ///
    /// # Arguments
    ///
    /// * `credential_id`: The credential ID to look up
    ///
    /// # Returns
    ///
    /// Returns the passkey credential if found
    pub async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<torii_core::repositories::PasskeyCredential>, ToriiError> {
        let torii = self.torii();
        torii
            .passkey_service
            .get_credential(credential_id)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Authenticate with a passkey credential and create session
    ///
    /// # Arguments
    ///
    /// * `credential_id`: The credential ID from the WebAuthn response
    /// * `user_agent`: Optional user agent to associate with the session
    /// * `ip_address`: Optional IP address to associate with the session
    ///
    /// # Returns
    ///
    /// Returns the user and session if authentication succeeds
    pub async fn authenticate(
        &self,
        credential_id: &[u8],
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        let torii = self.torii();
        let user = torii
            .passkey_service
            .authenticate_credential(credential_id)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?
            .ok_or_else(|| ToriiError::AuthError("Invalid passkey credential".to_string()))?;

        let session = torii
            .create_session(&user.id, user_agent, ip_address)
            .await?;

        Ok((user, session))
    }

    /// Delete a passkey credential
    ///
    /// # Arguments
    ///
    /// * `credential_id`: The credential ID to delete
    ///
    /// # Returns
    ///
    /// Returns Ok() if the credential is deleted successfully
    pub async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), ToriiError> {
        let torii = self.torii();
        torii
            .passkey_service
            .delete_credential(credential_id)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    /// Delete all passkey credentials for a user
    ///
    /// # Arguments
    ///
    /// * `user_id`: The ID of the user to delete credentials for
    ///
    /// # Returns
    ///
    /// Returns Ok() if all credentials are deleted successfully
    pub async fn delete_user_credentials(&self, user_id: &UserId) -> Result<(), ToriiError> {
        let torii = self.torii();
        torii
            .passkey_service
            .delete_user_credentials(user_id)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }
}

// All namespace methods implemented!
