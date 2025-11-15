use crate::{
    Error, UserId,
    storage::{SecureToken, TokenPurpose},
    tenant::TenantId,
};
use async_trait::async_trait;
use chrono::Duration;

/// Repository for secure token data access
#[async_trait]
pub trait TokenRepository: Send + Sync + 'static {
    /// Create a new secure token for a specific purpose
    async fn create_token(
        &self,
        user_id: &UserId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error>;

    /// Verify and consume a secure token for a specific purpose
    ///
    /// This method ensures that tokens can only be used for their intended purpose,
    /// providing security isolation between different token types.
    async fn verify_token(
        &self,
        token: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error>;

    /// Check if a secure token is valid without consuming it
    ///
    /// This method checks if a token exists, has not expired, has not been used,
    /// and matches the expected purpose. Unlike verify_token, this method does not
    /// mark the token as used.
    async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error>;

    /// Clean up expired tokens for all purposes
    async fn cleanup_expired_tokens(&self) -> Result<(), Error>;

    // Tenant-scoped methods for multi-tenancy support

    /// Create a new secure token for a specific purpose within a specific tenant
    async fn create_token_in_tenant(
        &self,
        user_id: &UserId,
        tenant_id: &TenantId,
        purpose: TokenPurpose,
        expires_in: Duration,
    ) -> Result<SecureToken, Error>;

    /// Verify and consume a secure token for a specific purpose within a specific tenant
    async fn verify_token_in_tenant(
        &self,
        token: &str,
        purpose: TokenPurpose,
        tenant_id: &TenantId,
    ) -> Result<Option<SecureToken>, Error>;

    /// Check if a secure token is valid without consuming it within a specific tenant
    async fn check_token_in_tenant(&self, token: &str, purpose: TokenPurpose, tenant_id: &TenantId) -> Result<bool, Error>;

    /// Clean up expired tokens for all purposes within a specific tenant
    async fn cleanup_expired_tokens_in_tenant(&self, tenant_id: &TenantId) -> Result<(), Error>;

    /// List all tokens for a user within a specific tenant
    async fn list_user_tokens_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<SecureToken>, Error>;
}
