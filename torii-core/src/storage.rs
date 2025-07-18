use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::{
    Error, OAuthAccount, Session, User, UserId, error::utilities::RequiredFieldExt,
    session::SessionToken,
};

#[async_trait]
pub trait StoragePlugin: Send + Sync + 'static {
    type Config;

    /// Initialize storage with config
    async fn initialize(&self, config: Self::Config) -> Result<(), Error>;

    /// Storage health check
    async fn health_check(&self) -> Result<(), Error>;

    /// Clean up expired data
    async fn cleanup(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait UserStorage: Send + Sync + 'static {
    async fn create_user(&self, user: &NewUser) -> Result<User, Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error>;
    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Error>;
    async fn update_user(&self, user: &User) -> Result<User, Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Error>;
    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Error>;
}

#[async_trait]
pub trait SessionStorage: Send + Sync + 'static {
    async fn create_session(&self, session: &Session) -> Result<Session, Error>;
    async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error>;
    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error>;
    async fn cleanup_expired_sessions(&self) -> Result<(), Error>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error>;
}

/// Storage methods specific to email/password authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// storing and retrieving password hashes.
#[async_trait]
pub trait PasswordStorage: UserStorage {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error>;
}

/// Storage methods specific to OAuth authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// OAuth account management and PKCE verifier storage.
#[async_trait]
pub trait OAuthStorage: UserStorage {
    /// Create a new OAuth account linked to a user
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error>;

    /// Find a user by their OAuth provider and subject
    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error>;

    /// Find an OAuth account by provider and subject
    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error>;

    /// Link an existing user to an OAuth account
    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error>;

    /// Store a PKCE verifier with an expiration time
    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Error>;

    /// Retrieve a stored PKCE verifier by CSRF state
    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
}

impl NewUser {
    pub fn builder() -> NewUserBuilder {
        NewUserBuilder::default()
    }

    pub fn new(email: String) -> Self {
        NewUserBuilder::default()
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }

    pub fn with_id(id: UserId, email: String) -> Self {
        NewUserBuilder::default()
            .id(id)
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }
}

#[derive(Default)]
pub struct NewUserBuilder {
    id: Option<UserId>,
    email: Option<String>,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
}

impl NewUserBuilder {
    pub fn id(mut self, id: UserId) -> Self {
        self.id = Some(id);
        self
    }

    pub fn email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn email_verified_at(mut self, email_verified_at: Option<DateTime<Utc>>) -> Self {
        self.email_verified_at = email_verified_at;
        self
    }

    pub fn build(self) -> Result<NewUser, Error> {
        Ok(NewUser {
            id: self.id.unwrap_or_default(),
            email: self.email.require_field("Email")?,
            name: self.name,
            email_verified_at: self.email_verified_at,
        })
    }
}

/// Storage methods specific to passkey authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// storing and retrieving passkey credentials for a user.
#[async_trait]
pub trait PasskeyStorage: UserStorage {
    /// Add a passkey credential for a user
    async fn add_passkey(
        &self,
        user_id: &UserId,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), Error>;

    /// Get a passkey by credential ID
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, Error>;

    /// Get all passkeys for a user
    async fn get_passkeys(&self, user_id: &UserId) -> Result<Vec<String>, Error>;

    /// Set a passkey challenge for a user
    async fn set_passkey_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Error>;

    /// Get a passkey challenge
    async fn get_passkey_challenge(&self, challenge_id: &str) -> Result<Option<String>, Error>;
}

/// Purpose enumeration for secure tokens to ensure type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenPurpose {
    /// Tokens used for magic link authentication
    MagicLink,
    /// Tokens used for password reset flows
    PasswordReset,
    /// Tokens used for email verification (future)
    EmailVerification,
}

impl TokenPurpose {
    /// Get the string representation of the token purpose for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenPurpose::MagicLink => "magic_link",
            TokenPurpose::PasswordReset => "password_reset",
            TokenPurpose::EmailVerification => "email_verification",
        }
    }
}

impl FromStr for TokenPurpose {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use crate::error::StorageError;
        match s {
            "magic_link" => Ok(TokenPurpose::MagicLink),
            "password_reset" => Ok(TokenPurpose::PasswordReset),
            "email_verification" => Ok(TokenPurpose::EmailVerification),
            _ => Err(Error::Storage(StorageError::Database(format!(
                "Invalid token purpose: {s}"
            )))),
        }
    }
}

/// Generic secure token for various authentication purposes
#[derive(Debug, Clone)]
pub struct SecureToken {
    pub user_id: UserId,
    pub token: String,
    pub purpose: TokenPurpose,
    pub used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecureToken {
    pub fn new(
        user_id: UserId,
        token: String,
        purpose: TokenPurpose,
        used_at: Option<DateTime<Utc>>,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            token,
            purpose,
            used_at,
            expires_at,
            created_at,
            updated_at,
        }
    }

    pub fn used(&self) -> bool {
        self.used_at.is_some()
    }
}

impl PartialEq for SecureToken {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
            && self.token == other.token
            && self.purpose == other.purpose
            && self.used_at == other.used_at
            // Some databases may not store the timestamp with more precision than seconds, so we compare the timestamps as integers
            && self.expires_at.timestamp() == other.expires_at.timestamp()
            && self.created_at.timestamp() == other.created_at.timestamp()
            && self.updated_at.timestamp() == other.updated_at.timestamp()
    }
}

/// Storage methods for secure tokens
///
/// This trait provides storage for generic secure tokens that can be used
/// for various authentication purposes like magic links, password resets, and email verification.
#[async_trait]
pub trait TokenStorage: UserStorage {
    /// Save a secure token to storage
    async fn save_secure_token(&self, token: &SecureToken) -> Result<(), Error>;

    /// Get a secure token by its string value and purpose
    async fn get_secure_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error>;

    /// Mark a secure token as used
    async fn set_secure_token_used(&self, token: &str, purpose: TokenPurpose) -> Result<(), Error>;

    /// Clean up expired tokens for all purposes
    async fn cleanup_expired_secure_tokens(&self) -> Result<(), Error>;
}
