use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, OAuthAccount, Session, User, UserId, session::SessionId};

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
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error>;
    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error>;
    async fn update_user(&self, user: &User) -> Result<User, Self::Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait SessionStorage: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Self::Error>;
    async fn delete_session(&self, id: &SessionId) -> Result<(), Self::Error>;
    async fn cleanup_expired_sessions(&self) -> Result<(), Self::Error>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Self::Error>;
}

/// Storage methods specific to email/password authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// storing and retrieving password hashes.
#[async_trait]
pub trait EmailPasswordStorage: UserStorage {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Self::Error>;
}

/// Storage methods specific to OAuth authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// OAuth account management and nonce storage.
#[async_trait]
pub trait OAuthStorage: UserStorage {
    /// Create a new OAuth account linked to a user
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Self::Error>;

    /// Find a user by their OAuth provider and subject
    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Self::Error>;

    /// Find an OAuth account by provider and subject
    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Self::Error>;

    /// Link an existing user to an OAuth account
    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Self::Error>;

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

#[derive(Debug, Clone)]
pub struct Storage<U: UserStorage, S: SessionStorage> {
    user_storage: Arc<U>,
    session_storage: Arc<S>,
}

impl<U: UserStorage, S: SessionStorage> Storage<U, S> {
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            user_storage,
            session_storage,
        }
    }

    pub async fn create_user(&self, user: &NewUser) -> Result<User, U::Error> {
        self.user_storage.create_user(user).await
    }

    pub async fn get_user(&self, id: &UserId) -> Result<Option<User>, U::Error> {
        self.user_storage.get_user(id).await
    }

    pub async fn create_session(&self, session: &Session) -> Result<Session, S::Error> {
        self.session_storage.create_session(session).await
    }

    pub async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, S::Error> {
        self.session_storage.get_session(id).await
    }

    pub async fn delete_session(&self, id: &SessionId) -> Result<(), S::Error> {
        self.session_storage.delete_session(id).await
    }

    pub async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), S::Error> {
        self.session_storage.delete_sessions_for_user(user_id).await
    }

    pub fn user_storage(&self) -> Arc<U> {
        self.user_storage.clone()
    }

    pub fn session_storage(&self) -> Arc<S> {
        self.session_storage.clone()
    }
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

    pub fn email_verified_at(mut self, email_verified_at: DateTime<Utc>) -> Self {
        self.email_verified_at = Some(email_verified_at);
        self
    }

    pub fn build(self) -> Result<NewUser, Error> {
        Ok(NewUser {
            id: self.id.unwrap_or(UserId::new_random()),
            email: self
                .email
                .ok_or(Error::ValidationError("Email is required".to_string()))?,
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
    ) -> Result<(), Self::Error>;

    /// Get a passkey by credential ID
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, Self::Error>;

    /// Get all passkeys for a user
    async fn get_passkeys(&self, user_id: &UserId) -> Result<Vec<String>, Self::Error>;

    /// Set a passkey challenge for a user
    async fn set_passkey_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Self::Error>;

    /// Get a passkey challenge
    async fn get_passkey_challenge(
        &self,
        challenge_id: &str,
    ) -> Result<Option<String>, Self::Error>;
}
