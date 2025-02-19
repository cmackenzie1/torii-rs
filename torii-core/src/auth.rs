use async_trait::async_trait;
use std::collections::HashMap;

use crate::{Error, Session, User};

/// The credentials used to authenticate a user.
///
/// This is used to authenticate a user and create a session.
#[derive(Debug, Clone)]
pub enum Credentials {
    Password { email: String, password: String },
    OAuth { provider: String, token: String },
    Token(String),
}

impl Credentials {
    /// Create new email/password credentials
    pub fn email_password(email: String, password: String) -> Self {
        Self::Password { email, password }
    }

    /// Create new OAuth credentials
    pub fn oauth(provider: impl Into<String>, token: impl Into<String>) -> Self {
        Self::OAuth {
            provider: provider.into(),
            token: token.into(),
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
pub trait AuthPlugin: Send + Sync + 'static {
    /// Unique identifier for this auth method
    fn auth_method(&self) -> &str;

    /// Authenticate a user and create a session
    async fn authenticate(&self, credentials: &Credentials) -> Result<(User, Session), Error>;

    /// Validate an existing session
    async fn validate_session(&self, session: &Session) -> Result<bool, Error>;

    /// Handle logout/session termination
    async fn logout(&self, session: &Session) -> Result<(), Error>;
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Unique identifier for this auth provider
    fn provider_id(&self) -> &str;

    /// Authenticate a user with the given credentials
    async fn authenticate(&self, credentials: Credentials) -> Result<AuthResponse, Error>;

    /// Create a new user with the given credentials
    async fn create_user(&self, credentials: Credentials) -> Result<User, Error>;
}
