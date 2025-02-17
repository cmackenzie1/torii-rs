use async_trait::async_trait;
use std::collections::HashMap;

use crate::{Error, Session, User};

/// The credentials used to authenticate a user.
///
/// This is used to authenticate a user and create a session.
#[derive(Debug, Clone)]
pub enum Credentials {
    /// Email/password credentials.
    ///
    /// This is the default authentication method and is used for most plugins.
    EmailPassword { email: String, password: String },

    /// OAuth credentials.
    ///
    /// This is useful for plugins that need to authenticate with an OAuth provider.
    OAuth {
        provider: String,
        access_token: String,
        refresh_token: Option<String>,
    },

    /// Custom credentials from key-value pairs.
    ///
    /// This is useful for plugins that need to pass additional information to the authentication process
    /// without them having to be part of the core plugin system.
    Custom(HashMap<String, String>),
}

impl Credentials {
    /// Create new email/password credentials
    pub fn email_password(email: String, password: String) -> Self {
        Self::EmailPassword { email, password }
    }

    /// Create new OAuth credentials
    pub fn oauth(
        provider: impl Into<String>,
        access_token: impl Into<String>,
        refresh_token: Option<String>,
    ) -> Self {
        Self::OAuth {
            provider: provider.into(),
            access_token: access_token.into(),
            refresh_token,
        }
    }

    /// Create custom credentials from key-value pairs
    pub fn custom(fields: HashMap<String, String>) -> Self {
        Self::Custom(fields)
    }
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
