use async_trait::async_trait;
use chrono::Duration;
use sqlx::SqlitePool;
use torii_core::{
    Error, OAuthAccount, User, UserId, error::StorageError, repositories::OAuthRepository,
};

pub struct SqliteOAuthRepository {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl SqliteOAuthRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthRepository for SqliteOAuthRepository {
    async fn create_account(
        &self,
        _provider: &str,
        _subject: &str,
        _user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn find_user_by_provider(
        &self,
        _provider: &str,
        _subject: &str,
    ) -> Result<Option<User>, Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn find_account_by_provider(
        &self,
        _provider: &str,
        _subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn link_account(
        &self,
        _user_id: &UserId,
        _provider: &str,
        _subject: &str,
    ) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn store_pkce_verifier(
        &self,
        _csrf_state: &str,
        _pkce_verifier: &str,
        _expires_in: Duration,
    ) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn get_pkce_verifier(&self, _csrf_state: &str) -> Result<Option<String>, Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }

    async fn delete_pkce_verifier(&self, _csrf_state: &str) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "OAuth repository not yet implemented".to_string(),
        )))
    }
}
