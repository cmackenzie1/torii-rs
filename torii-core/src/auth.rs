use async_trait::async_trait;
use downcast_rs::{DowncastSync, impl_downcast};
use std::collections::HashMap;

use crate::{Error, Plugin, Session, User};

/// The credentials used to authenticate a user.
///
/// This is used to authenticate a user and create a session.
#[derive(Debug, Clone)]
pub enum Credentials {
    Password {
        email: String,
        password: String,
    },
    OAuth {
        provider: String,
        token: String,
        nonce_key: String,
    },
    Token(String),
}

impl Credentials {
    /// Create new email/password credentials
    pub fn email_password(email: String, password: String) -> Self {
        Self::Password { email, password }
    }

    /// Create new OAuth credentials
    pub fn oauth(
        provider: impl Into<String>,
        token: impl Into<String>,
        nonce_key: impl Into<String>,
    ) -> Self {
        Self::OAuth {
            provider: provider.into(),
            token: token.into(),
            nonce_key: nonce_key.into(),
        }
    }

    /// Create new token credentials
    pub fn token(token: impl Into<String>) -> Self {
        Self::Token(token.into())
    }
}

#[derive(Debug)]
pub struct AuthResponse {
    pub user: User,
    pub session: Session,
    pub metadata: HashMap<String, String>,
}

/// A plugin that can be used to authenticate a user.
///
/// This is used to authenticate a user and create a session.
#[async_trait]
pub trait AuthPlugin: Plugin + Send + Sync + 'static + DowncastSync {
    /// Unique identifier for this auth method
    fn auth_method(&self) -> String;

    /// Register a new user with this authentication method
    async fn register(&self, credentials: &Credentials) -> Result<AuthResponse, Error>;

    /// Authenticate a user and create a session
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResponse, Error>;

    /// Validate an existing session
    async fn validate_session(&self, session: &Session) -> Result<bool, Error>;

    /// Handle logout/session termination
    async fn logout(&self, session: &Session) -> Result<(), Error>;
}
impl_downcast!(sync AuthPlugin);
