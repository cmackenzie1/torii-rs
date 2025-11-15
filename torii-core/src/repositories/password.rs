use crate::{Error, UserId, tenant::TenantId};
use async_trait::async_trait;

/// Repository for password-related data access
#[async_trait]
pub trait PasswordRepository: Send + Sync + 'static {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error>;

    /// Remove a user's password hash
    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error>;

    // Tenant-scoped methods for multi-tenancy support

    /// Store a password hash for a user within a specific tenant
    async fn set_password_hash_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId, hash: &str) -> Result<(), Error>;

    /// Retrieve a user's password hash within a specific tenant
    async fn get_password_hash_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Option<String>, Error>;

    /// Remove a user's password hash within a specific tenant
    async fn remove_password_hash_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<(), Error>;
}
