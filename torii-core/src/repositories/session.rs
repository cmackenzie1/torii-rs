use crate::{Error, Session, UserId, session::SessionToken};
use async_trait::async_trait;

/// Repository for session data access
#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    /// Create a new session
    async fn create(&self, session: Session) -> Result<Session, Error>;

    /// Find a session by token
    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error>;

    /// Delete a session by token
    async fn delete(&self, token: &SessionToken) -> Result<(), Error>;

    /// Delete all sessions for a user
    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<(), Error>;
}
