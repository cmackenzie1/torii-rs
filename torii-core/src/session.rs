//! Session management
//!
//! This module contains the core session struct and related functionality.
//!
//! Sessions are used to track user sessions and are used to authenticate users. The core session struct is defined as follows:
//!
//! | Field        | Type             | Description                                            |
//! | ------------ | ---------------- | ------------------------------------------------------ |
//! | `id`         | `String`         | The unique identifier for the session.                 |
//! | `user_id`    | `String`         | The unique identifier for the user.                    |
//! | `user_agent` | `Option<String>` | The user agent of the client that created the session. |
//! | `ip_address` | `Option<String>` | The IP address of the client that created the session. |
//! | `created_at` | `DateTime`       | The timestamp when the session was created.            |
//! | `updated_at` | `DateTime`       | The timestamp when the session was last updated.       |
//! | `expires_at` | `DateTime`       | The timestamp when the session will expire.            |
use std::sync::Arc;

use crate::{
    Error, SessionStorage,
    error::{SessionError, StorageError, ValidationError},
    user::UserId,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionToken(String);

impl SessionToken {
    pub fn new(token: &str) -> Self {
        Self(token.to_string())
    }

    pub fn new_random() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::new_random()
    }
}

impl From<String> for SessionToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionToken {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The unique identifier for the session.
    pub token: SessionToken,

    /// The unique identifier for the user.
    pub user_id: UserId,

    /// The user agent of the client that created the session.
    pub user_agent: Option<String>,

    /// The IP address of the client that created the session.
    pub ip_address: Option<String>,

    /// The timestamp when the session was created.
    pub created_at: DateTime<Utc>,

    /// The timestamp when the session was last updated.
    pub updated_at: DateTime<Utc>,

    /// The timestamp when the session will expire.
    pub expires_at: DateTime<Utc>,
}

impl Session {
    pub fn builder() -> SessionBuilder {
        SessionBuilder::default()
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

#[derive(Default)]
pub struct SessionBuilder {
    token: Option<SessionToken>,
    user_id: Option<UserId>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
}

impl SessionBuilder {
    pub fn token(mut self, token: SessionToken) -> Self {
        self.token = Some(token);
        self
    }

    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn user_agent(mut self, user_agent: Option<String>) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub fn ip_address(mut self, ip_address: Option<String>) -> Self {
        self.ip_address = ip_address;
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    pub fn build(self) -> Result<Session, Error> {
        let now = Utc::now();
        Ok(Session {
            token: self.token.unwrap_or(SessionToken::new_random()),
            user_id: self.user_id.ok_or(ValidationError::MissingField(
                "User ID is required".to_string(),
            ))?,
            user_agent: self.user_agent,
            ip_address: self.ip_address,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
            expires_at: self.expires_at.unwrap_or(now + Duration::days(30)),
        })
    }
}

#[async_trait]
pub trait SessionManager {
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error>;
    async fn get_session(&self, id: &SessionToken) -> Result<Session, Error>;
    async fn delete_session(&self, id: &SessionToken) -> Result<(), Error>;
    async fn cleanup_expired_sessions(&self) -> Result<(), Error>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error>;
}

pub struct DefaultSessionManager<S: SessionStorage> {
    storage: Arc<S>,
}

impl<S: SessionStorage> DefaultSessionManager<S> {
    pub fn new(storage: Arc<S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<S: SessionStorage> SessionManager for DefaultSessionManager<S> {
    async fn create_session(
        &self,
        user_id: &UserId,
        user_agent: Option<String>,
        ip_address: Option<String>,
        duration: Duration,
    ) -> Result<Session, Error> {
        let session = Session::builder()
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

    async fn get_session(&self, id: &SessionToken) -> Result<Session, Error> {
        let session = self
            .storage
            .get_session(id)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        if let Some(session) = session {
            if session.is_expired() {
                self.delete_session(id).await?;
                return Err(Error::Session(SessionError::Expired));
            }
            Ok(session)
        } else {
            Err(Error::Session(SessionError::NotFound))
        }
    }

    async fn delete_session(&self, id: &SessionToken) -> Result<(), Error> {
        self.storage
            .delete_session(id)
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

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_session_id() {
        let id = SessionToken::new_random();
        assert_eq!(id.to_string(), id.0.to_string());
    }

    #[test]
    fn test_session() {
        let session = Session::builder()
            .user_id(UserId::new_random())
            .user_agent(Some("test".to_string()))
            .ip_address(Some("127.0.0.1".to_string()))
            .expires_at(Utc::now() + Duration::days(30))
            .build()
            .unwrap();

        assert_eq!(session.token.to_string(), session.token.0.to_string());
    }
}
