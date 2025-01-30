use sqlx::Database;
use sqlx::Pool;
use torii_core::plugin::CreateUserParams;
use torii_core::{Error, PluginManager, User};

#[cfg(feature = "sqlite")]
use sqlx::Sqlite;

/// Builder for configuring and creating a Torii instance
pub struct ToriiBuilder<DB: Database> {
    manager: PluginManager,
    _phantom: std::marker::PhantomData<DB>,
}

impl<DB: Database> Default for ToriiBuilder<DB> {
    fn default() -> Self {
        Self {
            manager: PluginManager::new(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<DB: Database> ToriiBuilder<DB> {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "email-auth")]
    pub fn with_email_auth(mut self) -> Self {
        self.manager
            .register(Box::new(torii_auth_email::EmailPasswordPlugin));
        self
    }

    #[cfg(feature = "oidc-auth")]
    pub fn with_oidc_auth(mut self) -> Self {
        self.manager.register(Box::new(torii_auth_oidc::OIDCPlugin));
        self
    }

    /// Build with all default enabled authentication methods
    pub fn with_defaults(mut self) -> Self {
        #[cfg(feature = "email-auth")]
        {
            self.manager
                .register(Box::new(torii_auth_email::EmailPasswordPlugin));
        }
        #[cfg(feature = "oidc-auth")]
        {
            self.manager.register(Box::new(torii_auth_oidc::OIDCPlugin));
        }
        self
    }

    #[cfg(feature = "sqlite")]
    pub async fn setup_sqlite(self, pool: &Pool<Sqlite>) -> Result<Torii<Sqlite>, Error> {
        self.manager.setup(pool).await?;
        self.manager.migrate(pool).await?;

        Ok(Torii {
            manager: self.manager,
            pool: pool.clone(),
        })
    }
}

/// Main Torii authentication instance
pub struct Torii<DB: Database> {
    manager: PluginManager,
    pool: Pool<DB>,
}

#[cfg(feature = "sqlite")]
impl Torii<Sqlite> {
    /// Create a new SQLite-based Torii instance with default configuration
    pub async fn sqlite(pool: Pool<Sqlite>) -> Result<Self, Error> {
        ToriiBuilder::<Sqlite>::new()
            .with_defaults()
            .setup_sqlite(&pool)
            .await
    }

    pub async fn create_user(&self, params: &CreateUserParams) -> Result<User, Error> {
        match params {
            CreateUserParams::EmailPassword { email, password } => {
                let plugin = self
                    .manager
                    .get_plugin::<torii_auth_email::EmailPasswordPlugin>(
                        &torii_auth_email::PLUGIN_ID,
                    )?;

                let user = plugin.create_user(&self.pool, email, password).await?;

                Ok(user)
            }
            CreateUserParams::OIDC {
                provider: _,
                subject: _,
            } => {
                todo!()
            }
            _ => {
                Err(Error::UnsupportedAuthMethod(
                    self.manager
                        .plugins
                        .keys()
                        .cloned()
                        .map(|id| id.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                ))
            }
        }
    }
}

// Example usage in user's application:
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    #[tokio::test]
    async fn test_basic_setup() -> Result<(), Error> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;

        // Quick setup with defaults
        let _torii = Torii::sqlite(pool.clone()).await?;

        // Or more detailed configuration
        let _torii = ToriiBuilder::<Sqlite>::new()
            .with_email_auth()
            // Add more configuration here
            .setup_sqlite(&pool)
            .await?;

        Ok(())
    }
}
