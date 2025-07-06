use crate::{Error, Session, SessionProvider, SessionToken, UserId};
use chrono::Duration;
use std::sync::Arc;

/// Service for session management operations
pub struct SessionService<P: SessionProvider> {
    provider: Arc<P>,
}

impl<P: SessionProvider> SessionService<P> {
    /// Create a new SessionService with the given provider
    pub fn new(provider: Arc<P>) -> Self {
        Self { provider }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        expires_in: Duration,
    ) -> Result<Session, Error> {
        self.provider
            .create_session(user_id, user_agent, ip_address, expires_in)
            .await
    }

    /// Get a session by token
    pub async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        match self.provider.get_session(token).await {
            Ok(session) => Ok(Some(session)),
            Err(crate::Error::Session(crate::error::SessionError::NotFound)) => Ok(None),
            Err(crate::Error::Session(crate::error::SessionError::Expired)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Delete a session
    pub async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        self.provider.delete_session(token).await
    }

    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.delete_sessions_for_user(user_id).await
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        self.provider.cleanup_expired_sessions().await
    }
}
