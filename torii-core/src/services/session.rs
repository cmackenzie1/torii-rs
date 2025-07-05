use crate::{Error, Session, UserId, repositories::SessionRepository, session::SessionToken};
use chrono::{Duration, Utc};
use std::sync::Arc;

/// Service for session management operations
pub struct SessionService<R: SessionRepository> {
    repository: Arc<R>,
}

impl<R: SessionRepository> SessionService<R> {
    /// Create a new SessionService with the given repository
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        expires_in: Duration,
    ) -> Result<Session, Error> {
        let now = Utc::now();
        let session = Session {
            token: SessionToken::new_random(),
            user_id: user_id.clone(),
            user_agent,
            ip_address,
            created_at: now,
            updated_at: now,
            expires_at: now + expires_in,
        };

        self.repository.create(session).await
    }

    /// Get a session by token
    pub async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        let session = self.repository.find_by_token(token).await?;

        // Check if session is expired
        if let Some(ref s) = session {
            if s.expires_at < Utc::now() {
                return Ok(None);
            }
        }

        Ok(session)
    }

    /// Delete a session
    pub async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        self.repository.delete(token).await
    }

    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: &UserId) -> Result<(), Error> {
        self.repository.delete_by_user_id(user_id).await
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        self.repository.cleanup_expired().await
    }
}
