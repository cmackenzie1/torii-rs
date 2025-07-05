use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    User, UserId, OAuthAccount, Error,
    repositories::OAuthRepository,
};
use crate::SeaORMStorage;
use chrono::Duration;

pub struct SeaORMOAuthRepository {
    storage: SeaORMStorage,
}

impl SeaORMOAuthRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl OAuthRepository for SeaORMOAuthRepository {
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        self.storage.create_oauth_account(provider, subject, user_id).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        self.storage.get_user_by_oauth_provider(provider, subject).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.storage.get_oauth_account_by_provider(provider, subject).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        self.storage.link_oauth_account(user_id, provider, subject).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.storage.store_pkce_verifier(csrf_state, pkce_verifier, expires_in).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        self.storage.get_pkce_verifier(csrf_state).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
        self.storage.delete_pkce_verifier(csrf_state).await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }
}