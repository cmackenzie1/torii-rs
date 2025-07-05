//! Repository implementations for SeaORM storage

pub mod magic_link;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod user;

pub use magic_link::SeaORMMagicLinkRepository;
pub use oauth::SeaORMOAuthRepository;
pub use passkey::SeaORMPasskeyRepository;
pub use password::SeaORMPasswordRepository;
pub use session::SeaORMSessionRepository;
pub use user::SeaORMUserRepository;

use crate::SeaORMStorageError;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use torii_core::{Error, error::StorageError, repositories::RepositoryProvider};

/// Repository provider implementation for SeaORM
pub struct SeaORMRepositoryProvider {
    pool: DatabaseConnection,
    user: Arc<SeaORMUserRepository>,
    session: Arc<SeaORMSessionRepository>,
    password: Arc<SeaORMPasswordRepository>,
    oauth: Arc<SeaORMOAuthRepository>,
    passkey: Arc<SeaORMPasskeyRepository>,
    magic_link: Arc<SeaORMMagicLinkRepository>,
}

impl SeaORMRepositoryProvider {
    pub fn new(pool: DatabaseConnection) -> Self {
        let user = Arc::new(SeaORMUserRepository::new(pool.clone()));
        let session = Arc::new(SeaORMSessionRepository::new(pool.clone()));
        let password = Arc::new(SeaORMPasswordRepository::new(pool.clone()));
        let oauth = Arc::new(SeaORMOAuthRepository::new(pool.clone()));
        let passkey = Arc::new(SeaORMPasskeyRepository::new(pool.clone()));
        let magic_link = Arc::new(SeaORMMagicLinkRepository::new(pool.clone()));

        Self {
            pool,
            user,
            session,
            password,
            oauth,
            passkey,
            magic_link,
        }
    }
}

#[async_trait]
impl RepositoryProvider for SeaORMRepositoryProvider {
    type User = SeaORMUserRepository;
    type Session = SeaORMSessionRepository;
    type Password = SeaORMPasswordRepository;
    type OAuth = SeaORMOAuthRepository;
    type Passkey = SeaORMPasskeyRepository;
    type MagicLink = SeaORMMagicLinkRepository;
    type Error = Error;

    fn user(&self) -> &Self::User {
        &self.user
    }

    fn session(&self) -> &Self::Session {
        &self.session
    }

    fn password(&self) -> &Self::Password {
        &self.password
    }

    fn oauth(&self) -> &Self::OAuth {
        &self.oauth
    }

    fn passkey(&self) -> &Self::Passkey {
        &self.passkey
    }

    fn magic_link(&self) -> &Self::MagicLink {
        &self.magic_link
    }

    async fn migrate(&self) -> Result<(), Self::Error> {
        use crate::migrations::Migrator;
        use sea_orm_migration::MigratorTrait;

        Migrator::up(&self.pool, None)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), Self::Error> {
        self.pool
            .ping()
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}

impl From<SeaORMStorageError> for Error {
    fn from(err: SeaORMStorageError) -> Self {
        Error::Storage(StorageError::Database(err.to_string()))
    }
}
