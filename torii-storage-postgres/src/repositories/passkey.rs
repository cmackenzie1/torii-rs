//! PostgreSQL implementation of the passkey repository.

use async_trait::async_trait;
use sqlx::PgPool;
use torii_core::{
    Error, UserId,
    error::StorageError,
    repositories::{PasskeyCredential, PasskeyRepository},
};

/// PostgreSQL repository for passkey data.
pub struct PostgresPasskeyRepository {
    #[allow(dead_code)]
    pool: PgPool,
}

impl PostgresPasskeyRepository {
    /// Create a new PostgreSQL passkey repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasskeyRepository for PostgresPasskeyRepository {
    async fn add_credential(
        &self,
        _user_id: &UserId,
        _credential_id: Vec<u8>,
        _public_key: Vec<u8>,
        _name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }

    async fn get_credentials_for_user(
        &self,
        _user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }

    async fn get_credential(
        &self,
        _credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }

    async fn update_last_used(&self, _credential_id: &[u8]) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }

    async fn delete_credential(&self, _credential_id: &[u8]) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }

    async fn delete_all_for_user(&self, _user_id: &UserId) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "Passkey repository not yet implemented".to_string(),
        )))
    }
}
