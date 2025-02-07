use std::sync::Arc;

use sqlx::Pool;
use sqlx::Sqlite;
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
    ) -> Self {
        self.manager.register(torii_auth_oidc::OIDCPlugin::new(
            provider.to_string(),
            client_id.to_string(),
            client_secret.to_string(),
            redirect_uri.to_string(),
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
/// let user = torii.create_user(&CreateUserParams::EmailPassword {
///     email: "test@example.com".to_string(),
///     password: "password".to_string(),
/// }).await?;
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

    pub async fn create_user(&self, email: &str, password: &str) -> Result<User, Error> {
        let plugin = self
            .manager
            .get_plugin::<torii_auth_email::EmailPasswordPlugin>("email_password")
            .ok_or(Error::UnsupportedAuthMethod("email_password".to_string()))?;

        let user = plugin
            .create_user(self.manager.storage(), email, password)
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
    async fn test_create_user() -> Result<(), Error> {
        let torii = setup_torii().await?;

        let user = torii.create_user("test@example.com", "password").await?;

        assert_eq!(user.email, "test@example.com");

        Ok(())
    }
}
