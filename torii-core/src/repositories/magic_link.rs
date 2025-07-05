use crate::{Error, storage::MagicToken};
use async_trait::async_trait;
use chrono::Duration;

/// Repository for magic link token data access
#[async_trait]
pub trait MagicLinkRepository: Send + Sync + 'static {
    /// Create a new magic token
    async fn create_token(&self, email: &str, expires_in: Duration) -> Result<MagicToken, Error>;

    /// Verify and consume a magic token
    async fn verify_token(&self, token: &str) -> Result<Option<String>, Error>;

    /// Clean up expired tokens
    async fn cleanup_expired_tokens(&self) -> Result<(), Error>;
}
