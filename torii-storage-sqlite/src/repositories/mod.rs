//! Repository implementations for SQLite storage

pub mod magic_link;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod user;

pub use magic_link::SqliteMagicLinkRepository;
pub use oauth::SqliteOAuthRepository;
pub use passkey::SqlitePasskeyRepository;
pub use password::SqlitePasswordRepository;
pub use session::SqliteSessionRepository;
pub use user::SqliteUserRepository;

use async_trait::async_trait;
use sqlx::SqlitePool;
use std::sync::Arc;
use torii_core::{Error, error::StorageError, repositories::RepositoryProvider};

/// Repository provider implementation for SQLite
pub struct SqliteRepositoryProvider {
    pool: SqlitePool,
    user: Arc<SqliteUserRepository>,
    session: Arc<SqliteSessionRepository>,
    password: Arc<SqlitePasswordRepository>,
    oauth: Arc<SqliteOAuthRepository>,
    passkey: Arc<SqlitePasskeyRepository>,
    magic_link: Arc<SqliteMagicLinkRepository>,
}

impl SqliteRepositoryProvider {
    pub fn new(pool: SqlitePool) -> Self {
        let user = Arc::new(SqliteUserRepository::new(pool.clone()));
        let session = Arc::new(SqliteSessionRepository::new(pool.clone()));
        let password = Arc::new(SqlitePasswordRepository::new(pool.clone()));
        let oauth = Arc::new(SqliteOAuthRepository::new(pool.clone()));
        let passkey = Arc::new(SqlitePasskeyRepository::new(pool.clone()));
        let magic_link = Arc::new(SqliteMagicLinkRepository::new(pool.clone()));

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
impl RepositoryProvider for SqliteRepositoryProvider {
    type User = SqliteUserRepository;
    type Session = SqliteSessionRepository;
    type Password = SqlitePasswordRepository;
    type OAuth = SqliteOAuthRepository;
    type Passkey = SqlitePasskeyRepository;
    type MagicLink = SqliteMagicLinkRepository;

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

    async fn migrate(&self) -> Result<(), torii_core::Error> {
        use crate::migrations::{
            CreateIndexes, CreateMagicLinksTable, CreateOAuthAccountsTable,
            CreatePasskeyChallengesTable, CreatePasskeysTable, CreateSessionsTable,
            CreateUsersTable, SqliteMigrationManager,
        };
        use torii_migration::{Migration, MigrationManager};

        let manager = SqliteMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            Error::Storage(StorageError::Database(
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
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            Error::Storage(StorageError::Database(
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
