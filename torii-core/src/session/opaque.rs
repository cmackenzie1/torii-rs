//! Opaque session provider implementation
//!
//! This module provides a stateful session provider using opaque tokens
//! backed by persistent storage (database).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, Utc};

use crate::{
    Error, Session, SessionStorage, SessionToken, UserId,
    error::{SessionError, StorageError},
};

use super::provider::SessionProvider;

/// Opaque token session provider
///
/// This provider creates random opaque tokens and stores session data
/// in a persistent storage backend. Each session lookup requires a
/// database query.
pub struct OpaqueSessionProvider<S: SessionStorage> {
    storage: Arc<S>,
}

impl<S: SessionStorage> OpaqueSessionProvider<S> {
    /// Create a new opaque session provider with the given storage backend
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S: SessionStorage> SessionProvider for OpaqueSessionProvider<S> {
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error> {
        let session = Session::builder()
            .token(SessionToken::new_random())
            .user_id(user_id.clone())
            .user_agent(user_agent)
            .ip_address(ip_address)
            .expires_at(Utc::now() + duration)
            .build()?;

        let session = self
            .storage
            .create_session(&session)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(session)
    }

    async fn get_session(&self, token: &SessionToken) -> Result<Session, Error> {
        let session = self
            .storage
            .get_session(token)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        if let Some(session) = session {
            if session.is_expired() {
                self.delete_session(token).await?;
                return Err(Error::Session(SessionError::Expired));
            }
            Ok(session)
        } else {
            Err(Error::Session(SessionError::NotFound))
        }
    }

    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        self.storage
            .delete_session(token)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        self.storage
            .cleanup_expired_sessions()
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage
            .delete_sessions_for_user(user_id)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }
}
