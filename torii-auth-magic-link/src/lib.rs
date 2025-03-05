//! Magic Link authentication plugin for Torii
//!
//! This plugin provides magic link authentication functionality, allowing users to sign in by clicking
//! a secure link sent to their email address rather than using a password.
//!
//! # Features
//!
//! - Generate secure one-time use magic links
//! - Verify magic link tokens
//! - Automatic user creation if not exists
//! - Configurable token expiration
//!
//! # Example
//!
//! ```rust,no_run
//! use torii_auth_magic_link::MagicLinkPlugin;
//! use torii_core::plugin::PluginManager;
//!
//! // Register the plugin with your PluginManager
//! let mut plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());
//! plugin_manager.register_plugin(MagicLinkPlugin::new(user_storage.clone()));
//!
//! // Generate a magic link token
//! let plugin = plugin_manager.get_plugin::<MagicLinkPlugin>("magic_link").unwrap();
//! let token = plugin.generate_magic_token("user@example.com").await?;
//!
//! // Verify the token when user clicks the link
//! let user = plugin.verify_magic_token(&token.token).await?;
//! ```
use std::sync::Arc;

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::TryRngCore;
use torii_core::{
    Plugin, UserStorage,
    storage::{MagicLinkStorage, MagicToken},
};

#[derive(Debug, thiserror::Error)]
pub enum MagicLinkError {
    #[error("User not found")]
    UserNotFound,

    #[error("Token expired")]
    TokenExpired,

    #[error("Token already used")]
    TokenAlreadyUsed,

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Magic Link authentication plugin
///
/// This plugin provides magic link authentication functionality, allowing users to sign in by clicking
/// a secure link sent to their email address rather than using a password.
///
/// # Features
///
/// - Generate secure one-time use magic links
/// - Verify magic link tokens
/// - Automatic user creation if not exists
///
/// # Example
///
/// ```rust,no_run
/// use torii_auth_magic_link::MagicLinkPlugin;
/// use torii_core::plugin::PluginManager;
///
/// // Register the plugin with your PluginManager
/// let mut plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());
/// plugin_manager.register_plugin(MagicLinkPlugin::new(user_storage.clone()));
///
/// // Generate a magic link token
/// let plugin = plugin_manager.get_plugin::<MagicLinkPlugin>("magic_link").unwrap();
/// let token = plugin.generate_magic_token("user@example.com").await?;
///
/// // Verify the token when user clicks the link
/// let user = plugin.verify_magic_token(&token.token).await?;
/// ```
pub struct MagicLinkPlugin<U: UserStorage> {
    user_storage: Arc<U>,
}

impl<U> Plugin for MagicLinkPlugin<U>
where
    U: UserStorage,
{
    fn name(&self) -> String {
        "magic_link".to_string()
    }
}

impl<U> MagicLinkPlugin<U>
where
    U: MagicLinkStorage,
{
    pub fn new(user_storage: Arc<U>) -> Self {
        Self { user_storage }
    }

    pub async fn generate_magic_token(&self, email: &str) -> Result<MagicToken, MagicLinkError> {
        let user = self
            .user_storage
            .get_or_create_user_by_email(email)
            .await
            .map_err(|e| MagicLinkError::StorageError(e.to_string()))?;

        let now = Utc::now();
        let token = MagicToken::new(
            user.id,
            generate_secure_token(),
            None,
            now + chrono::Duration::minutes(10),
            now,
            now,
        );

        self.user_storage
            .save_magic_token(&token)
            .await
            .map_err(|e| MagicLinkError::StorageError(e.to_string()))?;

        Ok(token)
    }

    pub async fn verify_magic_token(&self, token: &str) -> Result<MagicToken, MagicLinkError> {
        let token = self
            .user_storage
            .get_magic_token(token)
            .await
            .map_err(|e| MagicLinkError::StorageError(e.to_string()))?
            .ok_or(MagicLinkError::UserNotFound)?;

        if token.expires_at < Utc::now() {
            return Err(MagicLinkError::TokenExpired);
        }

        if token.used() {
            return Err(MagicLinkError::TokenAlreadyUsed);
        }

        self.user_storage
            .set_magic_token_used(&token.token)
            .await
            .map_err(|e| MagicLinkError::StorageError(e.to_string()))?;

        Ok(token)
    }
}

/// Generate a secure token
///
/// This function generates a secure token using the `rand` crate.
/// The token is encoded using the `BASE64_URL_SAFE_NO_PAD` engine.
///
/// # Returns
/// A secure token as a string
///
/// # Example
///
/// ```rust,no_run
/// let token = generate_secure_token();
/// ```
fn generate_secure_token() -> String {
    let mut token = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut token)
        .expect("Failed to generate secure bytes");
    encode_token(&token)
}

fn encode_token(token: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(token)
}

#[cfg(test)]
mod tests {
    use torii_storage_sqlite::SqliteStorage;

    use super::*;

    async fn setup_sqlite_storage() -> Arc<SqliteStorage> {
        let storage = SqliteStorage::connect("sqlite::memory:").await.unwrap();
        storage.migrate().await.unwrap();
        Arc::new(storage)
    }

    #[tokio::test]
    async fn test_magic_link_plugin() {
        let user_storage = setup_sqlite_storage().await;
        let plugin = MagicLinkPlugin::new(user_storage);
        assert_eq!(plugin.name(), "magic_link");
    }

    #[tokio::test]
    async fn test_generate_magic_token() {
        let user_storage = setup_sqlite_storage().await;
        let plugin = MagicLinkPlugin::new(user_storage);
        let token = plugin
            .generate_magic_token("test@example.com")
            .await
            .unwrap();
        assert_ne!(token.token, "");
    }

    #[tokio::test]
    async fn test_verify_magic_token() {
        let user_storage = setup_sqlite_storage().await;
        let plugin = MagicLinkPlugin::new(user_storage);
        let token = plugin
            .generate_magic_token("test@example.com")
            .await
            .unwrap();
        let verified_token = plugin.verify_magic_token(&token.token).await.unwrap();
        assert_eq!(token, verified_token);
    }
}
