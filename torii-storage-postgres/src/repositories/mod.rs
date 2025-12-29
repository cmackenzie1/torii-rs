//! Repository implementations for PostgreSQL storage

pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod token;
pub mod user;

pub use oauth::PostgresOAuthRepository;
pub use passkey::PostgresPasskeyRepository;
pub use password::PostgresPasswordRepository;
pub use session::PostgresSessionRepository;
pub use token::PostgresTokenRepository;
pub use user::PostgresUserRepository;

use crate::PostgresBruteForceRepository;
use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use torii_core::{
    Error,
    error::StorageError,
    repositories::{
        BruteForceRepositoryProvider, OAuthRepositoryProvider, PasskeyRepositoryProvider,
        PasswordRepositoryProvider, RepositoryProvider, SessionRepositoryProvider,
        TokenRepositoryProvider, UserRepositoryProvider,
    },
};

/// Repository provider implementation for PostgreSQL.
///
/// This struct implements all the individual repository provider traits
/// as well as the unified `RepositoryProvider` trait.
pub struct PostgresRepositoryProvider {
    pool: PgPool,
    user: Arc<PostgresUserRepository>,
    session: Arc<PostgresSessionRepository>,
    password: Arc<PostgresPasswordRepository>,
    oauth: Arc<PostgresOAuthRepository>,
    passkey: Arc<PostgresPasskeyRepository>,
    token: Arc<PostgresTokenRepository>,
    brute_force: Arc<PostgresBruteForceRepository>,
}

impl PostgresRepositoryProvider {
    /// Create a new PostgreSQL repository provider.
    pub fn new(pool: PgPool) -> Self {
        let user = Arc::new(PostgresUserRepository::new(pool.clone()));
        let session = Arc::new(PostgresSessionRepository::new(pool.clone()));
        let password = Arc::new(PostgresPasswordRepository::new(pool.clone()));
        let oauth = Arc::new(PostgresOAuthRepository::new(pool.clone()));
        let passkey = Arc::new(PostgresPasskeyRepository::new(pool.clone()));
        let token = Arc::new(PostgresTokenRepository::new(pool.clone()));
        let brute_force = Arc::new(PostgresBruteForceRepository::new(pool.clone()));

        Self {
            pool,
            user,
            session,
            password,
            oauth,
            passkey,
            token,
            brute_force,
        }
    }
}

// Implement individual provider traits

impl UserRepositoryProvider for PostgresRepositoryProvider {
    type UserRepo = PostgresUserRepository;

    fn user(&self) -> &Self::UserRepo {
        &self.user
    }
}

impl SessionRepositoryProvider for PostgresRepositoryProvider {
    type SessionRepo = PostgresSessionRepository;

    fn session(&self) -> &Self::SessionRepo {
        &self.session
    }
}

impl PasswordRepositoryProvider for PostgresRepositoryProvider {
    type PasswordRepo = PostgresPasswordRepository;

    fn password(&self) -> &Self::PasswordRepo {
        &self.password
    }
}

impl OAuthRepositoryProvider for PostgresRepositoryProvider {
    type OAuthRepo = PostgresOAuthRepository;

    fn oauth(&self) -> &Self::OAuthRepo {
        &self.oauth
    }
}

impl PasskeyRepositoryProvider for PostgresRepositoryProvider {
    type PasskeyRepo = PostgresPasskeyRepository;

    fn passkey(&self) -> &Self::PasskeyRepo {
        &self.passkey
    }
}

impl TokenRepositoryProvider for PostgresRepositoryProvider {
    type TokenRepo = PostgresTokenRepository;

    fn token(&self) -> &Self::TokenRepo {
        &self.token
    }
}

impl BruteForceRepositoryProvider for PostgresRepositoryProvider {
    type BruteForceRepo = PostgresBruteForceRepository;

    fn brute_force(&self) -> &Self::BruteForceRepo {
        &self.brute_force
    }
}

// Implement the unified RepositoryProvider trait

#[async_trait]
impl RepositoryProvider for PostgresRepositoryProvider {
    async fn migrate(&self) -> Result<(), Error> {
        use crate::migrations::{
            AddLockedAtToUsers, CreateFailedLoginAttemptsTable, CreateIndexes,
            CreateOAuthAccountsTable, CreatePasskeyChallengesTable, CreatePasskeysTable,
            CreateSessionsTable, CreateUsersTable, PostgresMigrationManager,
        };
        use torii_migration::{Migration, MigrationManager};

        let manager = PostgresMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            Error::Storage(StorageError::Migration(
                "Failed to initialize migrations".to_string(),
            ))
        })?;

        let migrations: Vec<Box<dyn Migration<_>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
            Box::new(CreateIndexes),
            Box::new(CreateFailedLoginAttemptsTable),
            Box::new(AddLockedAtToUsers),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            Error::Storage(StorageError::Migration(
                "Failed to run migrations".to_string(),
            ))
        })?;

        Ok(())
    }

    async fn health_check(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}
