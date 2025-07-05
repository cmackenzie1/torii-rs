use crate::{Error, OAuthAccount, User, UserId};
use async_trait::async_trait;
use chrono::Duration;

/// Repository for OAuth-related data access
#[async_trait]
pub trait OAuthRepository: Send + Sync + 'static {
    /// Create a new OAuth account linked to a user
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error>;

    /// Find a user by their OAuth provider and subject
    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error>;

    /// Find an OAuth account by provider and subject
    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error>;

    /// Link an existing user to an OAuth account
    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error>;

    /// Store a PKCE verifier with an expiration time
    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error>;

    /// Retrieve a stored PKCE verifier by CSRF state
    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error>;

    /// Delete a PKCE verifier
    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error>;
}
