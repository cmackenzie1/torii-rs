use crate::{Error, Session, UserId, session::SessionToken, tenant::TenantId};
use async_trait::async_trait;

/// Repository for session data access
#[async_trait]
pub trait SessionRepository: Send + Sync + 'static {
    /// Create a new session
    async fn create(&self, session: Session) -> Result<Session, Error>;

    /// Find a session by token
    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error>;

    /// Delete a session by token
    async fn delete(&self, token: &SessionToken) -> Result<(), Error>;

    /// Delete all sessions for a user
    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error>;

    /// Clean up expired sessions
    async fn cleanup_expired(&self) -> Result<(), Error>;

    // Tenant-scoped methods for multi-tenancy support

    /// Find a session by token within a specific tenant
    async fn find_by_token_in_tenant(&self, token: &SessionToken, tenant_id: &TenantId) -> Result<Option<Session>, Error>;

    /// Delete a session by token within a tenant (with tenant validation)
    async fn delete_in_tenant(&self, token: &SessionToken, tenant_id: &TenantId) -> Result<(), Error>;

    /// Delete all sessions for a user within a specific tenant
    async fn delete_by_user_id_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<(), Error>;

    /// List all sessions for a user within a specific tenant
    async fn list_user_sessions_in_tenant(&self, user_id: &UserId, tenant_id: &TenantId) -> Result<Vec<Session>, Error>;

    /// Count sessions within a specific tenant
    async fn count_sessions_in_tenant(&self, tenant_id: &TenantId) -> Result<u64, Error>;

    /// Clean up expired sessions within a specific tenant
    async fn cleanup_expired_in_tenant(&self, tenant_id: &TenantId) -> Result<(), Error>;
}
