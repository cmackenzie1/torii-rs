use std::sync::Arc;
use chrono::Duration;
use crate::{
    User, UserId, OAuthAccount, Error,
    error::AuthError,
    repositories::{UserRepository, OAuthRepository},
};

/// Service for OAuth authentication operations
pub struct OAuthService<U: UserRepository, O: OAuthRepository> {
    user_repository: Arc<U>,
    oauth_repository: Arc<O>,
}

impl<U: UserRepository, O: OAuthRepository> OAuthService<U, O> {
    /// Create a new OAuthService with the given repositories
    pub fn new(user_repository: Arc<U>, oauth_repository: Arc<O>) -> Self {
        Self {
            user_repository,
            oauth_repository,
        }
    }

    /// Create or get a user from OAuth provider information
    pub async fn get_or_create_user(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
        _name: Option<String>,
    ) -> Result<User, Error> {
        // First try to find existing user by OAuth provider
        if let Some(user) = self.oauth_repository
            .find_user_by_provider(provider, subject)
            .await?
        {
            return Ok(user);
        }

        // If not found, try to find by email and link the account
        let user = if let Some(existing_user) = self.user_repository.find_by_email(email).await? {
            // Link existing user to OAuth account
            self.oauth_repository
                .link_account(&existing_user.id, provider, subject)
                .await?;
            existing_user
        } else {
            // Create new user
            let new_user = self.user_repository.find_or_create_by_email(email).await?;
            
            // Create OAuth account
            self.oauth_repository
                .create_account(provider, subject, &new_user.id)
                .await?;
            
            new_user
        };

        Ok(user)
    }

    /// Link an existing user to an OAuth account
    pub async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        // Check if this OAuth account is already linked to another user
        if (self.oauth_repository
            .find_user_by_provider(provider, subject)
            .await?).is_some()
        {
            return Err(Error::Auth(AuthError::AccountAlreadyLinked));
        }

        self.oauth_repository
            .link_account(user_id, provider, subject)
            .await
    }

    /// Store a PKCE verifier
    pub async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.oauth_repository
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
    }

    /// Get and consume a PKCE verifier
    pub async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        let verifier = self.oauth_repository
            .get_pkce_verifier(csrf_state)
            .await?;

        if verifier.is_some() {
            // Delete the verifier after retrieving it (one-time use)
            self.oauth_repository
                .delete_pkce_verifier(csrf_state)
                .await?;
        }

        Ok(verifier)
    }

    /// Get OAuth account information
    pub async fn get_account(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.oauth_repository
            .find_account_by_provider(provider, subject)
            .await
    }
}