use std::sync::Arc;

use sqlx::Pool;
use sqlx::Sqlite;
use torii_core::plugin::CreateUserParams;
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
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            manager: PluginManager::new(user_storage, session_storage),
        }
    }

    #[cfg(feature = "email-auth")]
    pub fn with_email_auth(mut self) -> Self {
        self.manager
            .register(torii_auth_email::EmailPasswordPlugin::new());
        self
    }

    #[cfg(feature = "oidc-auth")]
    pub fn with_oidc_auth(mut self) -> Self {
        self.manager.register(torii_auth_oidc::OIDCPlugin::new(
            "google".to_string(),
            std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
            std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
            "http://localhost:4000/auth/oidc/callback".to_string(),
        ));
        self
    }

    /// Build with all default enabled authentication methods
    pub fn with_defaults(mut self) -> Self {
        #[cfg(feature = "email-auth")]
        {
            self.manager.register(torii_auth_email::EmailPasswordPlugin);
        }
        #[cfg(feature = "oidc-auth")]
        {
            self.manager.register(torii_auth_oidc::OIDCPlugin::new(
                "google".to_string(),
                std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
                std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
                "http://localhost:4000/auth/oidc/callback".to_string(),
            ));
        }
        self
    }

    #[cfg(feature = "sqlite")]
    pub async fn setup_sqlite(self) -> Result<Torii<U, S>, Error> {
        self.manager.setup().await?;

        Ok(Torii {
            manager: self.manager,
        })
    }
}

/// Main Torii authentication instance
pub struct Torii<U: UserStorage, S: SessionStorage> {
    manager: PluginManager<U, S>,
}

#[cfg(feature = "sqlite")]
impl Torii<SqliteStorage, SqliteStorage> {
    /// Create a new SQLite-based Torii instance with default configuration
    pub async fn sqlite(pool: Pool<Sqlite>) -> Result<Self, Error> {
        ToriiBuilder::<SqliteStorage, SqliteStorage>::new(
            Arc::new(SqliteStorage::new(pool.clone())),
            Arc::new(SqliteStorage::new(pool.clone())),
        )
        .with_defaults()
        .setup_sqlite()
        .await
    }

    pub async fn create_user(&self, params: &CreateUserParams) -> Result<User, Error> {
        match params {
            CreateUserParams::EmailPassword { email, password } => {
                let plugin = self
                    .manager
                    .get_plugin::<torii_auth_email::EmailPasswordPlugin>()
                    .ok_or(Error::UnsupportedAuthMethod("email_password".to_string()))?;

                let user = plugin
                    .create_user(self.manager.storage(), email, password)
                    .await?;

                Ok(user)
            }
            CreateUserParams::OIDC {
                provider: _,
                subject: _,
            } => {
                todo!()
            }
            _ => Err(Error::UnsupportedAuthMethod("".to_string())),
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
        let _torii = ToriiBuilder::<SqliteStorage, SqliteStorage>::new(
            Arc::new(SqliteStorage::new(pool.clone())),
            Arc::new(SqliteStorage::new(pool.clone())),
        )
        .with_email_auth()
        .setup_sqlite()
        .await?;

        Ok(())
    }
}
