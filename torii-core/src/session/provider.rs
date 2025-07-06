//! Session provider trait and implementations
//!
//! This module defines the SessionProvider trait which abstracts the creation
//! and validation of session tokens, allowing for both stateful (database-backed)
//! and stateless (JWT) session implementations.

use async_trait::async_trait;
use chrono::Duration;

use crate::{Error, Session, SessionToken, UserId};

/// Trait for session token providers
///
/// This trait abstracts the creation and validation of session tokens,
/// allowing for different implementations such as JWT tokens or
/// database-backed opaque tokens.
#[async_trait]
pub trait SessionProvider: Send + Sync {
    /// Create a new session token for the given user
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user to create a session for
    /// * `user_agent` - Optional user agent string
    /// * `ip_address` - Optional IP address
    /// * `duration` - How long the session should be valid for
    ///
    /// # Returns
    /// A new Session with an appropriate token
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error>;

    /// Validate and retrieve session information from a token
    ///
    /// # Arguments
    /// * `token` - The session token to validate
    ///
    /// # Returns
    /// The Session if the token is valid, or an error if invalid/expired
    async fn get_session(&self, token: &SessionToken) -> Result<Session, Error>;

    /// Invalidate a session token
    ///
    /// For stateless providers (like JWT), this may be a no-op.
    /// For stateful providers, this should remove the session from storage.
    ///
    /// # Arguments
    /// * `token` - The session token to invalidate
    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error>;

    /// Clean up expired sessions
    ///
    /// For stateless providers (like JWT), this is typically a no-op.
    /// For stateful providers, this should remove expired sessions from storage.
    async fn cleanup_expired_sessions(&self) -> Result<(), Error>;

    /// Invalidate all sessions for a specific user
    ///
    /// # Arguments
    /// * `user_id` - The ID of the user whose sessions should be invalidated
    ///
    /// # Note
    /// For stateless providers like JWT, this may not be fully supported
    /// without implementing a token blacklist or revocation mechanism.
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error>;
}

/// Implementation of SessionProvider for Box<dyn SessionProvider>
/// This allows for dynamic dispatch of session providers
#[async_trait]
impl SessionProvider for Box<dyn SessionProvider> {
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error> {
        (**self)
            .create_session(user_id, user_agent, ip_address, duration)
            .await
    }

    async fn get_session(&self, token: &SessionToken) -> Result<Session, Error> {
        (**self).get_session(token).await
    }

    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        (**self).delete_session(token).await
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        (**self).cleanup_expired_sessions().await
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        (**self).delete_sessions_for_user(user_id).await
    }
}
