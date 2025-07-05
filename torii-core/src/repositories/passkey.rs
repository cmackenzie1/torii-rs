use crate::{Error, UserId};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Represents a stored passkey credential
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub user_id: UserId,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Repository for passkey-related data access
#[async_trait]
pub trait PasskeyRepository: Send + Sync + 'static {
    /// Add a passkey credential for a user
    async fn add_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error>;

    /// Get all passkey credentials for a user
    async fn get_credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error>;

    /// Get a specific passkey credential
    async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error>;

    /// Update the last used timestamp for a credential
    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error>;

    /// Delete a passkey credential
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error>;

    /// Delete all passkey credentials for a user
    async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error>;
}
