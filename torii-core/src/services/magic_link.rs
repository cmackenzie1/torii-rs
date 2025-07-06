use crate::{
    Error, User,
    repositories::{MagicLinkRepository, UserRepository},
    services::UserService,
    storage::MagicToken,
};
use chrono::Duration;
use std::sync::Arc;

/// Service for magic link authentication operations
pub struct MagicLinkService<U: UserRepository, M: MagicLinkRepository> {
    user_service: Arc<UserService<U>>,
    magic_link_repository: Arc<M>,
}

impl<U: UserRepository, M: MagicLinkRepository> MagicLinkService<U, M> {
    /// Create a new MagicLinkService with the given repositories
    pub fn new(user_repository: Arc<U>, magic_link_repository: Arc<M>) -> Self {
        let user_service = Arc::new(UserService::new(user_repository));
        Self {
            user_service,
            magic_link_repository,
        }
    }

    /// Generate a magic token for a user
    pub async fn generate_token(&self, email: &str) -> Result<MagicToken, Error> {
        // Ensure user exists (or create them) - email validation happens in UserService
        let _user = self.user_service.get_or_create_user(email).await?;

        // Generate the token with default expiration (15 minutes)
        let expires_in = Duration::minutes(15);
        self.magic_link_repository
            .create_token(email, expires_in)
            .await
    }

    /// Generate a magic token with custom expiration
    pub async fn generate_token_with_expiration(
        &self,
        email: &str,
        expires_in: Duration,
    ) -> Result<MagicToken, Error> {
        // Ensure user exists (or create them) - email validation happens in UserService
        let _user = self.user_service.get_or_create_user(email).await?;

        self.magic_link_repository
            .create_token(email, expires_in)
            .await
    }

    /// Verify a magic token and return the associated user
    pub async fn verify_token(&self, token: &str) -> Result<Option<User>, Error> {
        // Verify and consume the token
        let email = self.magic_link_repository.verify_token(token).await?;

        if let Some(email) = email {
            // Get the user by email
            let user = self.user_service.get_user_by_email(&email).await?;
            Ok(user)
        } else {
            Ok(None)
        }
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.magic_link_repository.cleanup_expired_tokens().await
    }
}
