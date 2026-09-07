use chrono::Duration;
use std::sync::Arc;
use torii_core::{Error, Session, SessionProvider, SessionToken, UserId, events::Event};

use crate::{EventBus, EventEmitter};

/// Service for session management operations
pub struct SessionService<P: SessionProvider> {
    provider: Arc<P>,
    event_bus: Option<Arc<EventBus>>,
}

#[async_trait::async_trait]
impl<P: SessionProvider> EventEmitter for SessionService<P> {
    fn event_bus(&self) -> Option<&Arc<EventBus>> {
        self.event_bus.as_ref()
    }
}

impl<P: SessionProvider> SessionService<P> {
    /// Create a new SessionService with the given provider
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider,
            event_bus: None,
        }
    }

    /// Enable lifecycle event emission for this service.
    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        expires_in: Duration,
    ) -> Result<Session, Error> {
        let session = self
            .provider
            .create_session(user_id, user_agent, ip_address, expires_in)
            .await?;
        self.emit_event(Event::SessionCreated(user_id.clone(), session.clone()))
            .await?;
        Ok(session)
    }

    /// Get a session by token
    pub async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        match self.provider.get_session(token).await {
            Ok(session) => Ok(Some(session)),
            Err(torii_core::Error::Session(torii_core::error::SessionError::NotFound)) => Ok(None),
            Err(torii_core::Error::Session(torii_core::error::SessionError::Expired)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// List all sessions for a user
    pub async fn list_sessions_for_user(&self, user_id: &UserId) -> Result<Vec<Session>, Error> {
        self.provider.list_sessions_for_user(user_id).await
    }

    /// Delete a session
    pub async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        let session = self.get_session(token).await?;
        self.provider.delete_session(token).await?;
        if let Some(session) = session {
            self.emit_event(Event::SessionDeleted(session.user_id, token.clone()))
                .await?;
        }
        Ok(())
    }

    /// Delete all sessions for a user
    pub async fn delete_user_sessions(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.delete_sessions_for_user(user_id).await?;
        self.emit_event(Event::SessionsCleared(user_id.clone()))
            .await?;
        Ok(())
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        self.provider.cleanup_expired_sessions().await
    }

    /// Refresh a session by extending its expiration time
    pub async fn refresh_session(
        &self,
        token: &SessionToken,
        duration: Duration,
    ) -> Result<Session, Error> {
        let session = self.provider.refresh_session(token, duration).await?;
        self.emit_event(Event::SessionRefreshed(
            session.user_id.clone(),
            session.clone(),
        ))
        .await?;
        Ok(session)
    }
}
