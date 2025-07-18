use crate::{
    Error, OAuthAccount, Session, SessionStorage, User, UserId,
    repositories::{
        OAuthRepository, PasskeyCredential, PasskeyRepository, PasswordRepository,
        RepositoryProvider, SessionRepository, TokenRepository, UserRepository,
    },
    session::SessionToken,
    storage::{NewUser, SecureToken, TokenPurpose},
};
use async_trait::async_trait;
use chrono::Duration;
use std::sync::Arc;

/// Adapter that wraps a RepositoryProvider and implements individual repository traits
pub struct UserRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> UserRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> UserRepository for UserRepositoryAdapter<R> {
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

pub struct SessionRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> SessionRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> SessionRepository for SessionRepositoryAdapter<R> {
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

/// Implementation of SessionStorage for SessionRepositoryAdapter
/// This allows the adapter to be used with the OpaqueSessionProvider
#[async_trait]
impl<R: RepositoryProvider> SessionStorage for SessionRepositoryAdapter<R> {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        self.create(session.clone()).await
    }

    async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        self.find_by_token(token).await
    }

    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error> {
        self.delete(token).await
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        self.cleanup_expired().await
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.delete_by_user_id(user_id).await
    }
}

pub struct PasswordRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> PasswordRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> PasswordRepository for PasswordRepositoryAdapter<R> {
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

pub struct OAuthRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> OAuthRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> OAuthRepository for OAuthRepositoryAdapter<R> {
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

pub struct PasskeyRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> PasskeyRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> PasskeyRepository for PasskeyRepositoryAdapter<R> {
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

/// Adapter that wraps a RepositoryProvider and implements TokenRepository
pub struct TokenRepositoryAdapter<R: RepositoryProvider> {
    provider: Arc<R>,
}

impl<R: RepositoryProvider> TokenRepositoryAdapter<R> {
    pub fn new(provider: Arc<R>) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<R: RepositoryProvider> TokenRepository for TokenRepositoryAdapter<R> {
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
