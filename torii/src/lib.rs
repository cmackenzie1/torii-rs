use std::sync::Arc;

use torii_auth_email::EmailPasswordPlugin;
use torii_auth_oauth::{AuthorizationUrl, OAuthPlugin, providers::Provider};
use torii_auth_passkey::{PasskeyChallenge, PasskeyPlugin};
use torii_core::{
    PluginManager, SessionStorage,
    storage::{EmailPasswordStorage, OAuthStorage, PasskeyStorage, Storage, UserStorage},
};

/// Re-export core types
pub use torii_core::{
    session::{Session, SessionId},
    user::{User, UserId},
};

#[derive(Debug, thiserror::Error)]
pub enum ToriiError {
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("Auth error: {0}")]
    AuthError(String),
    #[error("Storage error: {0}")]
    StorageError(String),
}

pub struct Torii<U, S>
where
    U: UserStorage + Clone,
    S: SessionStorage + Clone,
{
    storage: Storage<U, S>,
    manager: PluginManager<U, S>,
}

impl<U, S> Torii<U, S>
where
    U: UserStorage + Clone,
    S: SessionStorage + Clone,
{
    pub fn new(user_storage: Arc<U>, session_storage: Arc<S>) -> Self {
        Self {
            storage: Storage::new(user_storage.clone(), session_storage.clone()),
            manager: PluginManager::new(user_storage, session_storage),
        }
    }

    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, ToriiError> {
        let user = self
            .storage
            .get_user(user_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;
        Ok(user)
    }
    pub async fn get_session(&self, session_id: &SessionId) -> Result<Option<Session>, ToriiError> {
        let session = self
            .storage
            .get_session(session_id)
            .await
            .map_err(|e| ToriiError::StorageError(e.to_string()))?;
        Ok(session)
    }
}

impl<U, S> Torii<U, S>
where
    U: EmailPasswordStorage + Clone,
    S: SessionStorage + Clone,
{
    pub fn with_email_password_plugin(mut self) -> Self {
        let plugin = EmailPasswordPlugin::new(self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    pub async fn register_user_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<User, ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<EmailPasswordPlugin<U, S>>("email_password")
            .ok_or(ToriiError::PluginNotFound("email_password".to_string()))?;

        let user = password_plugin
            .register_user_with_password(email, password, None)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(user)
    }

    pub async fn login_user_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(User, Session), ToriiError> {
        let password_plugin = self
            .manager
            .get_plugin::<EmailPasswordPlugin<U, S>>("email_password")
            .ok_or(ToriiError::PluginNotFound("email_password".to_string()))?;

        let (user, session) = password_plugin
            .login_user_with_password(email, password)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }
}

impl<U, S> Torii<U, S>
where
    U: OAuthStorage + Clone,
    S: SessionStorage + Clone,
{
    pub fn with_oauth_provider(mut self, provider: Provider) -> Self {
        let plugin = OAuthPlugin::new(provider, self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    pub async fn get_oauth_authorization_url(
        &self,
        provider: &str,
    ) -> Result<AuthorizationUrl, ToriiError> {
        let oauth_plugin = self
            .manager
            .get_plugin::<OAuthPlugin<U, S>>(provider)
            .ok_or(ToriiError::PluginNotFound(provider.to_string()))?;

        let url = oauth_plugin
            .get_authorization_url()
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok(url)
    }
}

impl<U, S> Torii<U, S>
where
    U: PasskeyStorage + Clone,
    S: SessionStorage + Clone,
{
    pub fn with_passkey_plugin(mut self, rp_id: &str, rp_origin: &str) -> Self {
        let plugin = PasskeyPlugin::new(rp_id, rp_origin, self.storage.clone());
        self.manager.register_plugin(plugin);
        self
    }

    pub async fn begin_passkey_registration(
        &self,
        email: &str,
    ) -> Result<PasskeyChallenge, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        passkey_plugin
            .start_registration(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    pub async fn complete_passkey_registration(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let (user, session) = passkey_plugin
            .complete_registration(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }

    pub async fn begin_passkey_login(&self, email: &str) -> Result<PasskeyChallenge, ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        passkey_plugin
            .start_login(email)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))
    }

    pub async fn complete_passkey_login(
        &self,
        email: &str,
        challenge_id: &str,
        challenge_response: &serde_json::Value,
    ) -> Result<(User, Session), ToriiError> {
        let passkey_plugin = self
            .manager
            .get_plugin::<PasskeyPlugin<U, S>>("passkey")
            .ok_or(ToriiError::PluginNotFound("passkey".to_string()))?;

        let (user, session) = passkey_plugin
            .complete_login(email, challenge_id, challenge_response)
            .await
            .map_err(|e| ToriiError::AuthError(e.to_string()))?;

        Ok((user, session))
    }
}
