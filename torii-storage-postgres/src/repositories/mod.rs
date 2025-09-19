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

use async_trait::async_trait;
use sqlx::PgPool;
use std::sync::Arc;
use torii_core::{Error, error::StorageError, repositories::RepositoryProvider};
use torii_migration::{Migration, MigrationManager};

use crate::PostgresStorage;
use crate::migrations::{
    CreateIndexes, CreateOAuthAccountsTable, CreatePasskeyChallengesTable, CreatePasskeysTable,
    CreateSessionsTable, CreateUsersTable, PostgresMigrationManager,
};

/// Repository provider implementation for PostgreSQL
pub struct PostgresRepositoryProvider {
    pool: PgPool,
    user: Arc<PostgresUserRepository>,
    session: Arc<PostgresSessionRepository>,
    password: Arc<PostgresPasswordRepository>,
    oauth: Arc<PostgresOAuthRepository>,
    passkey: Arc<PostgresPasskeyRepository>,
    token: Arc<PostgresTokenRepository>,
}

impl PostgresRepositoryProvider {
    pub fn new(pool: PgPool) -> Self {
        let storage = PostgresStorage::new(pool.clone());
        let user = Arc::new(PostgresUserRepository::new(storage.clone()));
        let session = Arc::new(PostgresSessionRepository::new(storage.clone()));
        let password = Arc::new(PostgresPasswordRepository::new(storage.clone()));
        let oauth = Arc::new(PostgresOAuthRepository::new(storage.clone()));
        let passkey = Arc::new(PostgresPasskeyRepository::new(storage.clone()));
        let token = Arc::new(PostgresTokenRepository::new(storage));

        Self {
            pool,
            user,
            session,
            password,
            oauth,
            passkey,
            token,
        }
    }
}

#[async_trait]
impl RepositoryProvider for PostgresRepositoryProvider {
    type User = PostgresUserRepository;
    type Session = PostgresSessionRepository;
    type Password = PostgresPasswordRepository;
    type OAuth = PostgresOAuthRepository;
    type Passkey = PostgresPasskeyRepository;
    type Token = PostgresTokenRepository;

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

    fn token(&self) -> &Self::Token {
        &self.token
    }

    async fn migrate(&self) -> Result<(), Error> {
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
