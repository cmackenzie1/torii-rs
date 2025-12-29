//! Adapters that wrap RepositoryProvider implementations to implement individual repository traits.
//!
//! These adapters provide a way to use a RepositoryProvider implementation where individual
//! repository traits are expected. This is useful for dependency injection in services.

use crate::{
    Error, OAuthAccount, Session, User, UserId,
    repositories::{
        BruteForceProtectionRepository, BruteForceRepositoryProvider, OAuthRepository,
        OAuthRepositoryProvider, PasskeyCredential, PasskeyRepository, PasskeyRepositoryProvider,
        PasswordRepository, PasswordRepositoryProvider, SessionRepository,
        SessionRepositoryProvider, TokenRepository, TokenRepositoryProvider, UserRepository,
        UserRepositoryProvider,
    },
    session::SessionToken,
    storage::{AttemptStats, FailedLoginAttempt, NewUser, SecureToken, TokenPurpose},
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

/// Adapter that wraps a UserRepositoryProvider and implements UserRepository.
///
/// This adapter allows using a provider where a UserRepository is expected,
/// delegating all operations to the underlying provider.
pub struct UserRepositoryAdapter<R: UserRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: UserRepositoryProvider> UserRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: UserRepositoryProvider> UserRepository for UserRepositoryAdapter<R> {
    async fn create(&self, user: NewUser) -> Result<User, Error> {
        self.provider.user().create(user).await
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
        self.provider.user().find_by_id(id).await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.provider.user().find_by_email(email).await
    }

    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
        self.provider.user().find_or_create_by_email(email).await
    }

    async fn update(&self, user: &User) -> Result<User, Error> {
        self.provider.user().update(user).await
    }

    async fn delete(&self, id: &UserId) -> Result<(), Error> {
        self.provider.user().delete(id).await
    }

    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.user().mark_email_verified(user_id).await
    }
}

/// Adapter that wraps a SessionRepositoryProvider and implements SessionRepository.
pub struct SessionRepositoryAdapter<R: SessionRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: SessionRepositoryProvider> SessionRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: SessionRepositoryProvider> SessionRepository for SessionRepositoryAdapter<R> {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        self.provider.session().create(session).await
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        self.provider.session().find_by_token(token).await
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        self.provider.session().delete(token).await
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.session().delete_by_user_id(user_id).await
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        self.provider.session().cleanup_expired().await
    }
}

/// Adapter that wraps a PasswordRepositoryProvider and implements PasswordRepository.
pub struct PasswordRepositoryAdapter<R: PasswordRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: PasswordRepositoryProvider> PasswordRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: PasswordRepositoryProvider> PasswordRepository for PasswordRepositoryAdapter<R> {
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
        self.provider
            .password()
            .set_password_hash(user_id, hash)
            .await
    }

    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
        self.provider.password().get_password_hash(user_id).await
    }

    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.password().remove_password_hash(user_id).await
    }
}

/// Adapter that wraps an OAuthRepositoryProvider and implements OAuthRepository.
pub struct OAuthRepositoryAdapter<R: OAuthRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: OAuthRepositoryProvider> OAuthRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: OAuthRepositoryProvider> OAuthRepository for OAuthRepositoryAdapter<R> {
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        self.provider
            .oauth()
            .create_account(provider, subject, user_id)
            .await
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        self.provider
            .oauth()
            .find_user_by_provider(provider, subject)
            .await
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.provider
            .oauth()
            .find_account_by_provider(provider, subject)
            .await
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        self.provider
            .oauth()
            .link_account(user_id, provider, subject)
            .await
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.provider
            .oauth()
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        self.provider.oauth().get_pkce_verifier(csrf_state).await
    }

    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
        self.provider.oauth().delete_pkce_verifier(csrf_state).await
    }
}

/// Adapter that wraps a PasskeyRepositoryProvider and implements PasskeyRepository.
pub struct PasskeyRepositoryAdapter<R: PasskeyRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: PasskeyRepositoryProvider> PasskeyRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: PasskeyRepositoryProvider> PasskeyRepository for PasskeyRepositoryAdapter<R> {
    async fn add_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        self.provider
            .passkey()
            .add_credential(user_id, credential_id, public_key, name)
            .await
    }

    async fn get_credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        self.provider
            .passkey()
            .get_credentials_for_user(user_id)
            .await
    }

    async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        self.provider.passkey().get_credential(credential_id).await
    }

    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error> {
        self.provider
            .passkey()
            .update_last_used(credential_id)
            .await
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
        self.provider
            .passkey()
            .delete_credential(credential_id)
            .await
    }

    async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.provider.passkey().delete_all_for_user(user_id).await
    }
}

/// Adapter that wraps a TokenRepositoryProvider and implements TokenRepository.
pub struct TokenRepositoryAdapter<R: TokenRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: TokenRepositoryProvider> TokenRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: TokenRepositoryProvider> TokenRepository for TokenRepositoryAdapter<R> {
    async fn create_token(
        &self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error> {
        self.provider
            .token()
            .create_token(user_id, purpose, expires_in)
            .await
    }

    async fn verify_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error> {
        self.provider.token().verify_token(token, purpose).await
    }

    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
        self.provider.token().check_token(token, purpose).await
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.provider.token().cleanup_expired_tokens().await
    }
}

/// Adapter that wraps a BruteForceRepositoryProvider and implements BruteForceProtectionRepository.
///
/// This adapter delegates all operations to the underlying provider's brute force
/// repository, allowing services to work with the trait-based interface.
pub struct BruteForceProtectionRepositoryAdapter<R: BruteForceRepositoryProvider> {
    provider: Arc<R>,
}

impl<R: BruteForceRepositoryProvider> BruteForceProtectionRepositoryAdapter<R> {
    /// Create a new adapter wrapping the given repository provider.
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: BruteForceRepositoryProvider> BruteForceProtectionRepository
    for BruteForceProtectionRepositoryAdapter<R>
{
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        self.provider
            .brute_force()
            .record_failed_attempt(email, ip_address)
            .await
    }

    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        self.provider
            .brute_force()
            .get_attempt_stats(email, since)
            .await
    }

    async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
        self.provider.brute_force().clear_attempts(email).await
    }

    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        self.provider
            .brute_force()
            .cleanup_old_attempts(before)
            .await
    }

    async fn set_locked_at(
        &self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        self.provider
            .brute_force()
            .set_locked_at(email, locked_at)
            .await
    }

    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        self.provider.brute_force().get_locked_at(email).await
    }
}
