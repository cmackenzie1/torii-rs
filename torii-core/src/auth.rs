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
    Passkey {
        stage: String,
        email: String,
        challenge_response: Option<serde_json::Value>,
        metadata: HashMap<String, String>,
    },
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
    pub session: Option<Session>,
    pub metadata: HashMap<String, String>,
    pub passkey_challenge: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct AuthChallenge {
    /// The type of challenge (e.g., "webauthn_register", "webauthn_login")
    pub challenge_type: String,
    /// Challenge data to be sent to client
    pub challenge: serde_json::Value,
    /// Optional metadata to maintain state between stages
    pub metadata: HashMap<String, String>,
}

impl AuthChallenge {
    pub fn new(
        challenge_type: String,
        challenge: serde_json::Value,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            challenge_type,
            challenge,
            metadata,
        }
    }

    pub fn challenge_type(&self) -> &str {
        &self.challenge_type
    }

    pub fn challenge(&self) -> &serde_json::Value {
        &self.challenge
    }

    pub fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }
}

#[derive(Debug)]
pub enum AuthStage {
    /// The initial stage of authentication
    Start,
    /// A challenge to be sent to the client
    Challenge(AuthChallenge),
    /// The final stage of authentication
    Complete(AuthResponse),
}

/// A plugin that can be used to authenticate a user.
///
/// This is used to authenticate a user and create a session.
#[async_trait]
pub trait AuthPlugin: Plugin + Send + Sync + 'static + DowncastSync {
    /// Unique identifier for this auth method
    fn auth_method(&self) -> String;

    /// Register a new user with this authentication method
    async fn register(&self, credentials: &Credentials) -> Result<AuthStage, Error>;

    /// Authenticate a user and create a session
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthStage, Error>;

    /// Validate an existing session
    async fn validate_session(&self, session: &Session) -> Result<bool, Error>;

    /// Handle logout/session termination
    async fn logout(&self, session: &Session) -> Result<(), Error>;
}
impl_downcast!(sync AuthPlugin);
