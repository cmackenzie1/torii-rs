//! Torii - A flexible authentication framework for Rust
//!
//! Torii provides a pluggable authentication system that supports multiple
//! authentication methods and storage backends.
//!
//! # Example
//!
//! ```rust,no_run
//! use torii::{Torii, ToriiBuilder};
//! use torii_auth_email::EmailAuthPlugin;
//! use torii_storage_sqlite::SqliteStorage;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = SqliteStorage::new("torii.db").await?;
//!
//! let torii = ToriiBuilder::new(storage, storage)
//!     .with_email_auth()
//!     .setup_sqlite()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;

use sqlx::Pool;
use sqlx::Sqlite;
use torii_core::Session;
use torii_core::SessionStorage;
use torii_core::UserStorage;
use torii_core::{Error, PluginManager, User};

#[cfg(feature = "sqlite")]
use torii_storage_sqlite::SqliteStorage;

/// Builder for configuring and creating a Torii instance
pub struct ToriiBuilder<U: UserStorage, S: SessionStorage> {
    manager: PluginManager<U, S>,
}

impl<U, S> ToriiBuilder<U, S>
where
    U: UserStorage<Error = torii_core::Error>,
    S: SessionStorage<Error = torii_core::Error>,
{
    /// Create a new Torii instance with the given user storage and session storage.
    ///
    /// # Example
    /// ```
    /// let torii = ToriiBuilder::new(user_storage, session_storage)
    ///     .setup_sqlite()
    ///     .await?;
    /// ```
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            manager: PluginManager::new(user_storage, session_storage),
        }
    }

    /// Add an email authentication plugin to the Torii instance.
    ///
    /// # Example
    /// ```
    /// let torii = ToriiBuilder::new(user_storage, session_storage)
    ///     .with_email_auth()
    ///     .setup_sqlite()
    ///     .await?;
    /// ```
    #[cfg(feature = "email-auth")]
    pub fn with_email_auth(mut self) -> Self {
        self.manager
            .register(torii_auth_email::EmailPasswordPlugin::new());
        self
    }

    /// Setup the Torii instance with the given user storage and session storage using SQLite.
    ///
    /// # Example
    /// ```
    /// let torii = ToriiBuilder::new(user_storage, session_storage)
    ///     .setup_sqlite()
    ///     .await?;
    /// ```
    #[cfg(feature = "sqlite")]
    pub async fn setup_sqlite(self) -> Result<Torii<U, S>, Error> {
        self.manager.setup().await?;

        Ok(Torii {
            manager: self.manager,
        })
    }

    /// Add an OIDC provider to the Torii instance. Multiple OIDC providers can be added by calling this method multiple times.
    ///
    /// # Example
    /// ```
    /// let torii = ToriiBuilder::new(user_storage, session_storage)
    ///     .with_email_auth()
    ///     .with_oidc_provider("google", "client_id", "client_secret", "redirect_uri")
    ///     .setup_sqlite()
    ///     .await?;
    /// ```
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OIDC provider (e.g. "google", "github")
    /// * `client_id` - The client ID for the OIDC provider
    /// * `client_secret` - The client secret for the OIDC provider
    /// * `redirect_uri` - The redirect URI for the OIDC provider
    ///
    /// # Returns
    ///
    /// * `Self` - The builder instance
    #[cfg(feature = "oidc-auth")]
    pub fn with_oidc_provider(
        mut self,
        provider: &str,
        client_id: &str,
        client_secret: &str,
        redirect_uri: &str,
        issuer_url: &str,
        scopes: &[&str],
    ) -> Self {
        self.manager.register(torii_auth_oidc::OIDCPlugin::new(
            provider.to_string(),
            client_id.to_string(),
            client_secret.to_string(),
            redirect_uri.to_string(),
            issuer_url.to_string(),
            scopes.iter().map(|s| s.to_string()).collect(),
        ));
        self
    }
}

/// Main Torii authentication instance that can be used to create users and sessions
///
/// # Example
/// ```
/// let torii = ToriiBuilder::new(user_storage, session_storage)
///     .with_email_auth()
///     .setup_sqlite()
///     .await?;
///
/// let user = torii.create_user_with_email_password("test@example.com", "password").await?;
/// ```
pub struct Torii<U: UserStorage, S: SessionStorage> {
    manager: PluginManager<U, S>,
}

/// Create a new SQLite-based Torii instance with default configuration
///
/// # Example
/// ```
/// use sqlx::SqlitePool;
///
/// let pool = SqlitePool::connect("sqlite::memory:").await?;
/// let torii = Torii::sqlite(pool).await?;
/// ```
#[cfg(feature = "sqlite")]
impl Torii<SqliteStorage, SqliteStorage> {
    /// Create a new SQLite-based Torii instance with default configuration
    pub async fn sqlite(pool: Pool<Sqlite>) -> Result<Self, Error> {
        ToriiBuilder::<SqliteStorage, SqliteStorage>::new(
            Arc::new(SqliteStorage::new(pool.clone())),
            Arc::new(SqliteStorage::new(pool.clone())),
        )
        .with_email_auth()
        .setup_sqlite()
        .await
    }

    /// Create a new user with an email and password
    ///
    /// # Example
    /// ```
    /// let torii = Torii::sqlite(pool).await?;
    /// let user = torii.create_user_with_email_password("test@example.com", "password").await?;
    /// ```
    pub async fn create_user_with_email_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        let plugin = self
            .manager
            .get_plugin::<torii_auth_email::EmailPasswordPlugin>("email_password")
            .ok_or(Error::UnsupportedAuthMethod("email_password".to_string()))?;

        let user = plugin
            .create_user(self.manager.storage(), email, password)
            .await?;

        Ok(user)
    }

    /// Create a new session for a user
    ///
    /// # Example
    /// ```
    /// let torii = Torii::sqlite(pool).await?;
    /// let user = torii.create_user_with_email_password("test@example.com", "password").await?;
    /// let session = torii.create_session_for_user(&user).await?;
    /// ```
    pub async fn create_session_for_user(&self, user: &User) -> Result<Session, Error> {
        let session = Session::builder().user_id(user.id.clone()).build().unwrap();

        self.manager
            .storage()
            .session_storage()
            .create_session(&session)
            .await
    }

    /// Revoke a session
    ///
    /// # Example
    /// ```
    /// let torii = Torii::sqlite(pool).await?;
    /// let user = torii.create_user_with_email_password("test@example.com", "password").await?;
    /// let session = torii.create_session_for_user(&user).await?;
    /// let session = torii.revoke_session(&session).await?;
    /// ```
    pub async fn revoke_session(&self, session: &Session) -> Result<(), Error> {
        self.manager
            .storage()
            .session_storage()
            .delete_session(&session.id)
            .await
    }

    /// Create a new user with an OIDC provider
    ///
    /// # Example
    /// ```
    /// let torii = Torii::sqlite(pool).await?;
    /// let user = torii.create_user_with_oidc("google", "test@example.com", "1234567890").await?;
    /// ```
    #[cfg(feature = "oidc-auth")]
    pub async fn create_user_with_oidc(
        &self,
        provider: &str,
        email: &str,
        subject: &str,
    ) -> Result<User, Error> {
        let plugin = self
            .manager
            .get_plugin::<torii_auth_oidc::OIDCPlugin>(provider)
            .ok_or(Error::UnsupportedAuthMethod(provider.to_string()))?;

        let user = plugin
            .get_or_create_user(
                self.manager.storage(),
                email.to_string(),
                subject.to_string(),
            )
            .await?;

        Ok(user)
    }
}

// Example usage in user's application:
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn setup_torii() -> Result<Torii<SqliteStorage, SqliteStorage>, Error> {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let torii = Torii::sqlite(pool.clone()).await?;

        torii.manager.storage().user_storage().migrate().await?;
        torii.manager.storage().session_storage().migrate().await?;

        Ok(torii)
    }

    async fn setup_torii_with_oidc() -> Result<Torii<SqliteStorage, SqliteStorage>, Error> {
        let _ = tracing_subscriber::fmt::try_init();
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let torii = ToriiBuilder::<SqliteStorage, SqliteStorage>::new(
            Arc::new(SqliteStorage::new(pool.clone())),
            Arc::new(SqliteStorage::new(pool.clone())),
        )
        .with_email_auth()
        .with_oidc_provider(
            "google",
            "client_id",
            "client_secret",
            "redirect_uri",
            "https://accounts.google.com",
            &["email", "profile"],
        )
        .setup_sqlite()
        .await?;

        torii.manager.storage().user_storage().migrate().await?;
        torii.manager.storage().session_storage().migrate().await?;

        Ok(torii)
    }

    #[tokio::test]
    async fn test_basic_setup() -> Result<(), Error> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;

        // Quick setup with defaults
        let _torii = Torii::sqlite(pool.clone()).await?;

        // Or more detailed configuration
        let _torii = ToriiBuilder::<SqliteStorage, SqliteStorage>::new(
            Arc::new(SqliteStorage::new(pool.clone())),
            Arc::new(SqliteStorage::new(pool.clone())),
        )
        .with_email_auth()
        .setup_sqlite()
        .await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_create_user_with_email_password() -> Result<(), Error> {
        let torii = setup_torii().await?;

        let user = torii
            .create_user_with_email_password("test@example.com", "password")
            .await?;

        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_session_for_user() -> Result<(), Error> {
        let torii = setup_torii().await?;

        let user = torii
            .create_user_with_email_password("test@example.com", "password")
            .await?;

        let session = torii.create_session_for_user(&user).await?;

        assert_eq!(session.user_id, user.id);

        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_session() -> Result<(), Error> {
        let torii = setup_torii().await?;

        let user = torii
            .create_user_with_email_password("test@example.com", "password")
            .await?;

        let session = torii.create_session_for_user(&user).await?;

        torii.revoke_session(&session).await?;

        Ok(())
    }

    #[cfg(feature = "oidc-auth")]
    #[tokio::test]
    async fn test_create_user_with_oidc() -> Result<(), Error> {
        let torii = setup_torii_with_oidc().await?;

        let user = torii
            .create_user_with_oidc("google", "test@example.com", "1234567890")
            .await?;

        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[cfg(feature = "oidc-auth")]
    #[tokio::test]
    async fn test_create_session_for_user_with_oidc() -> Result<(), Error> {
        let torii = setup_torii_with_oidc().await?;

        let user = torii
            .create_user_with_oidc("google", "test@example.com", "1234567890")
            .await?;

        let session = torii.create_session_for_user(&user).await?;

        assert_eq!(session.user_id, user.id);

        Ok(())
    }
}
