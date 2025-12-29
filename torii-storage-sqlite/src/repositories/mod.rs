//! Repository implementations for SQLite storage

pub mod brute_force;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod token;
pub mod user;

pub use brute_force::SqliteBruteForceRepository;
pub use oauth::SqliteOAuthRepository;
pub use passkey::SqlitePasskeyRepository;
pub use password::SqlitePasswordRepository;
pub use session::SqliteSessionRepository;
pub use token::SqliteTokenRepository;
pub use user::SqliteUserRepository;

use async_trait::async_trait;
use sqlx::SqlitePool;
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

/// Repository provider implementation for SQLite
///
/// This struct implements all the individual repository provider traits
/// as well as the unified `RepositoryProvider` trait.
pub struct SqliteRepositoryProvider {
    pool: SqlitePool,
    user: Arc<SqliteUserRepository>,
    session: Arc<SqliteSessionRepository>,
    password: Arc<SqlitePasswordRepository>,
    oauth: Arc<SqliteOAuthRepository>,
    passkey: Arc<SqlitePasskeyRepository>,
    token: Arc<SqliteTokenRepository>,
    brute_force: Arc<SqliteBruteForceRepository>,
}

impl SqliteRepositoryProvider {
    pub fn new(pool: SqlitePool) -> Self {
        let user = Arc::new(SqliteUserRepository::new(pool.clone()));
        let session = Arc::new(SqliteSessionRepository::new(pool.clone()));
        let password = Arc::new(SqlitePasswordRepository::new(pool.clone()));
        let oauth = Arc::new(SqliteOAuthRepository::new(pool.clone()));
        let passkey = Arc::new(SqlitePasskeyRepository::new(pool.clone()));
        let token = Arc::new(SqliteTokenRepository::new(pool.clone()));
        let brute_force = Arc::new(SqliteBruteForceRepository::new(pool.clone()));

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

impl UserRepositoryProvider for SqliteRepositoryProvider {
    type UserRepo = SqliteUserRepository;

    fn user(&self) -> &Self::UserRepo {
        &self.user
    }
}

impl SessionRepositoryProvider for SqliteRepositoryProvider {
    type SessionRepo = SqliteSessionRepository;

    fn session(&self) -> &Self::SessionRepo {
        &self.session
    }
}

impl PasswordRepositoryProvider for SqliteRepositoryProvider {
    type PasswordRepo = SqlitePasswordRepository;

    fn password(&self) -> &Self::PasswordRepo {
        &self.password
    }
}

impl OAuthRepositoryProvider for SqliteRepositoryProvider {
    type OAuthRepo = SqliteOAuthRepository;

    fn oauth(&self) -> &Self::OAuthRepo {
        &self.oauth
    }
}

impl PasskeyRepositoryProvider for SqliteRepositoryProvider {
    type PasskeyRepo = SqlitePasskeyRepository;

    fn passkey(&self) -> &Self::PasskeyRepo {
        &self.passkey
    }
}

impl TokenRepositoryProvider for SqliteRepositoryProvider {
    type TokenRepo = SqliteTokenRepository;

    fn token(&self) -> &Self::TokenRepo {
        &self.token
    }
}

impl BruteForceRepositoryProvider for SqliteRepositoryProvider {
    type BruteForceRepo = SqliteBruteForceRepository;

    fn brute_force(&self) -> &Self::BruteForceRepo {
        &self.brute_force
    }
}

// Implement the unified RepositoryProvider trait

#[async_trait]
impl RepositoryProvider for SqliteRepositoryProvider {
    async fn migrate(&self) -> Result<(), torii_core::Error> {
        use crate::migrations::{
            AddLockedAtToUsers, CreateFailedLoginAttemptsTable, CreateIndexes,
            CreateOAuthAccountsTable, CreatePasskeyChallengesTable, CreatePasskeysTable,
            CreateSessionsTable, CreateUsersTable, SqliteMigrationManager,
        };
        use torii_migration::{Migration, MigrationManager};

        let manager = SqliteMigrationManager::new(self.pool.clone());
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

    async fn health_check(&self) -> Result<(), torii_core::Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }
}
