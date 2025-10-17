use crate::{Error, User, UserId, storage::NewUser, tenant::TenantId};
use async_trait::async_trait;

/// Repository for user data access
#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    /// Create a new user
    async fn create(&self, user: NewUser) -> Result<User, Error>;

    /// Find a user by ID
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error>;

    /// Find a user by email
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error>;

    /// Create a user if it doesn't exist, otherwise return the existing user
    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error>;

    /// Update an existing user
    async fn update(&self, user: &User) -> Result<User, Error>;

    /// Delete a user by ID
    async fn delete(&self, id: &UserId) -> Result<(), Error>;

    /// Mark a user's email as verified
    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error>;

    // Tenant-scoped methods for multi-tenancy support

    /// Find a user by ID within a specific tenant
    async fn find_by_id_in_tenant(&self, id: &UserId, tenant_id: &TenantId) -> Result<Option<User>, Error>;

    /// Find a user by email within a specific tenant
    async fn find_by_email_in_tenant(&self, email: &str, tenant_id: &TenantId) -> Result<Option<User>, Error>;

    /// Create a user if it doesn't exist within a tenant, otherwise return the existing user
    async fn find_or_create_by_email_in_tenant(&self, email: &str, tenant_id: &TenantId) -> Result<User, Error>;

    /// List all users within a specific tenant
    async fn list_users_in_tenant(&self, tenant_id: &TenantId, limit: Option<u32>, offset: Option<u32>) -> Result<Vec<User>, Error>;

    /// Count users within a specific tenant
    async fn count_users_in_tenant(&self, tenant_id: &TenantId) -> Result<u64, Error>;

    /// Mark a user's email as verified within a tenant (with tenant validation)
    async fn mark_email_verified_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<(), Error>;

    /// Delete a user by ID within a tenant (with tenant validation)
    async fn delete_in_tenant(&self, id: &UserId, tenant_id: &TenantId) -> Result<(), Error>;
}
