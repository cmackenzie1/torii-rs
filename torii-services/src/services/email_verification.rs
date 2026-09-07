//! Email verification service
//!
//! This module provides functionality for email verification flows.

use chrono::Duration;
use std::sync::Arc;
use torii_core::{
    Error, User, UserId,
    events::Event,
    repositories::{TokenRepository, UserRepository},
    storage::{SecureToken, TokenPurpose},
};

use crate::{EventBus, EventEmitter};

/// Default expiration time for email verification tokens (24 hours)
const DEFAULT_TOKEN_EXPIRATION: Duration = Duration::hours(24);

/// Service for email verification operations
pub struct EmailVerificationService<U: UserRepository, T: TokenRepository> {
    user_repository: Arc<U>,
    token_repository: Arc<T>,
    event_bus: Option<Arc<EventBus>>,
}

#[async_trait::async_trait]
impl<U: UserRepository, T: TokenRepository> EventEmitter for EmailVerificationService<U, T> {
    fn event_bus(&self) -> Option<&Arc<EventBus>> {
        self.event_bus.as_ref()
    }
}

impl<U: UserRepository, T: TokenRepository> EmailVerificationService<U, T> {
    /// Create a new EmailVerificationService with the given repositories
    pub fn new(user_repository: Arc<U>, token_repository: Arc<T>) -> Self {
        Self {
            user_repository,
            token_repository,
            event_bus: None,
        }
    }

    /// Enable email verification event emission.
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Generate an email verification token for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to generate a verification token for
    ///
    /// # Returns
    ///
    /// Returns the generated secure token. The token value can be accessed
    /// via `token.token()` and should be included in the verification link.
    pub async fn generate_token(&self, user_id: &UserId) -> Result<SecureToken, Error> {
        self.generate_token_with_expiration(user_id, DEFAULT_TOKEN_EXPIRATION)
            .await
    }

    /// Generate an email verification token with a custom expiration time
    ///
    /// # Arguments
    ///
    /// * `user_id` - The ID of the user to generate a verification token for
    /// * `expires_in` - How long the token should be valid
    ///
    /// # Returns
    ///
    /// Returns the generated secure token
    pub async fn generate_token_with_expiration(
        &self,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        let token = self
            .token_repository
            .create_token(user_id, TokenPurpose::EmailVerification, expires_in)
            .await?;
        self.emit_event(Event::EmailVerificationRequested(user_id.clone()))
            .await?;
        Ok(token)
    }

    /// Verify an email verification token without consuming it
    ///
    /// This is useful for frontend validation before showing a confirmation page.
    ///
    /// # Arguments
    ///
    /// * `token` - The verification token to check
    ///
    /// # Returns
    ///
    /// Returns `true` if the token is valid and not expired
    pub async fn check_token(&self, token: &str) -> Result<bool, Error> {
        self.token_repository
            .check_token(token, TokenPurpose::EmailVerification)
            .await
    }

    /// Verify the token and mark the user's email as verified
    ///
    /// This consumes the token (marks it as used) and updates the user's
    /// `email_verified_at` timestamp.
    ///
    /// # Arguments
    ///
    /// * `token` - The verification token
    ///
    /// # Returns
    ///
    /// Returns the user whose email was verified
    pub async fn verify_email(&self, token: &str) -> Result<User, Error> {
        // Verify and consume the token
        let secure_token = self
            .token_repository
            .verify_token(token, TokenPurpose::EmailVerification)
            .await?
            .ok_or_else(|| {
                Error::Session(torii_core::error::SessionError::InvalidToken(
                    "Invalid or expired email verification token".to_string(),
                ))
            })?;

        // Mark the user's email as verified
        self.user_repository
            .mark_email_verified(&secure_token.user_id)
            .await?;

        // Get and return the updated user
        let user = self
            .user_repository
            .find_by_id(&secure_token.user_id)
            .await?
            .ok_or(Error::Storage(torii_core::error::StorageError::NotFound))?;
        self.emit_event(Event::EmailVerified(user.id.clone()))
            .await?;
        Ok(user)
    }

    /// Clean up expired email verification tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.token_repository.cleanup_expired_tokens().await
    }
}
