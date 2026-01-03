//! Repository implementations for SeaORM storage

pub mod brute_force;
pub mod invitation;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod token;
pub mod user;

pub use brute_force::SeaORMBruteForceRepository;
pub use invitation::SeaORMInvitationRepository;
pub use oauth::SeaORMOAuthRepository;
pub use passkey::SeaORMPasskeyRepository;
pub use password::SeaORMPasswordRepository;
pub use session::SeaORMSessionRepository;
pub use token::SeaORMTokenRepository;
pub use user::SeaORMUserRepository;

use crate::SeaORMStorageError;
use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use std::sync::Arc;
use torii_core::{
    Error,
    error::StorageError,
    repositories::{
        BruteForceRepositoryProvider, InvitationRepositoryProvider, OAuthRepositoryProvider,
        PasskeyRepositoryProvider, PasswordRepositoryProvider, RepositoryProvider,
        SessionRepositoryProvider, TokenRepositoryProvider, UserRepositoryProvider,
    },
};

/// Repository provider implementation for SeaORM
///
/// This struct implements all the individual repository provider traits
/// as well as the unified `RepositoryProvider` trait.
#[derive(Clone)]
pub struct SeaORMRepositoryProvider {
    pool: DatabaseConnection,
    user: Arc<SeaORMUserRepository>,
    session: Arc<SeaORMSessionRepository>,
    password: Arc<SeaORMPasswordRepository>,
    oauth: Arc<SeaORMOAuthRepository>,
    passkey: Arc<SeaORMPasskeyRepository>,
    token: Arc<SeaORMTokenRepository>,
    brute_force: Arc<SeaORMBruteForceRepository>,
    invitation: Arc<SeaORMInvitationRepository>,
}

impl SeaORMRepositoryProvider {
    pub fn new(pool: DatabaseConnection) -> Self {
        let user = Arc::new(SeaORMUserRepository::new(pool.clone()));
        let session = Arc::new(SeaORMSessionRepository::new(pool.clone()));
        let password = Arc::new(SeaORMPasswordRepository::new(pool.clone()));
        let oauth = Arc::new(SeaORMOAuthRepository::new(pool.clone()));
        let passkey = Arc::new(SeaORMPasskeyRepository::new(pool.clone()));
        let token = Arc::new(SeaORMTokenRepository::new(pool.clone()));
        let brute_force = Arc::new(SeaORMBruteForceRepository::new(pool.clone()));
        let invitation = Arc::new(SeaORMInvitationRepository::new(pool.clone()));

        Self {
            pool,
            user,
            session,
            password,
            oauth,
            passkey,
            token,
            brute_force,
            invitation,
        }
    }
}

// Implement individual provider traits

impl UserRepositoryProvider for SeaORMRepositoryProvider {
    type UserRepo = SeaORMUserRepository;

    fn user(&self) -> &Self::UserRepo {
        &self.user
    }
}

impl SessionRepositoryProvider for SeaORMRepositoryProvider {
    type SessionRepo = SeaORMSessionRepository;

    fn session(&self) -> &Self::SessionRepo {
        &self.session
    }
}

impl PasswordRepositoryProvider for SeaORMRepositoryProvider {
    type PasswordRepo = SeaORMPasswordRepository;

    fn password(&self) -> &Self::PasswordRepo {
        &self.password
    }
}

impl OAuthRepositoryProvider for SeaORMRepositoryProvider {
    type OAuthRepo = SeaORMOAuthRepository;

    fn oauth(&self) -> &Self::OAuthRepo {
        &self.oauth
    }
}

impl PasskeyRepositoryProvider for SeaORMRepositoryProvider {
    type PasskeyRepo = SeaORMPasskeyRepository;

    fn passkey(&self) -> &Self::PasskeyRepo {
        &self.passkey
    }
}

impl TokenRepositoryProvider for SeaORMRepositoryProvider {
    type TokenRepo = SeaORMTokenRepository;

    fn token(&self) -> &Self::TokenRepo {
        &self.token
    }
}

impl BruteForceRepositoryProvider for SeaORMRepositoryProvider {
    type BruteForceRepo = SeaORMBruteForceRepository;

    fn brute_force(&self) -> &Self::BruteForceRepo {
        &self.brute_force
    }
}

impl InvitationRepositoryProvider for SeaORMRepositoryProvider {
    type InvitationRepo = SeaORMInvitationRepository;

    fn invitation(&self) -> &Self::InvitationRepo {
        &self.invitation
    }
}

// Implement the unified RepositoryProvider trait

#[async_trait]
impl RepositoryProvider for SeaORMRepositoryProvider {
    async fn migrate(&self) -> Result<(), torii_core::Error> {
        use crate::migrations::Migrator;
        use sea_orm_migration::MigratorTrait;

        Migrator::up(&self.pool, None)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    async fn health_check(&self) -> Result<(), torii_core::Error> {
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
