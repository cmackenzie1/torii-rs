// Multi-Tenancy API Contracts for torii-rs
// This file defines the public API surface for tenant-scoped operations

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Core tenant types
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

#[derive(Debug, Clone)]
pub struct TenantContext {
    tenant_id: TenantId,
}

// Main tenant-scoped interface
pub struct TenantScoped<R: RepositoryProvider> {
    torii: Arc<Torii<R>>,
    tenant_context: TenantContext,
}

impl<R: RepositoryProvider> TenantScoped<R> {
    /// Access password authentication methods for this tenant
    pub fn password(&self) -> TenantPasswordAuth<R> {
        TenantPasswordAuth {
            tenant_scoped: self,
        }
    }

    /// Access OAuth authentication methods for this tenant
    pub fn oauth(&self) -> TenantOAuthAuth<R> {
        TenantOAuthAuth {
            tenant_scoped: self,
        }
    }

    /// Access passkey authentication methods for this tenant
    pub fn passkey(&self) -> TenantPasskeyAuth<R> {
        TenantPasskeyAuth {
            tenant_scoped: self,
        }
    }

    /// Access magic link authentication methods for this tenant
    pub fn magic_link(&self) -> TenantMagicLinkAuth<R> {
        TenantMagicLinkAuth {
            tenant_scoped: self,
        }
    }

    /// Get a user by ID within this tenant
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, ToriiError> {
        // Implementation validates user belongs to this tenant
    }

    /// Get a user by email within this tenant
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, ToriiError> {
        // Implementation scopes query to this tenant
    }

    /// List all users in this tenant
    pub async fn list_users(&self) -> Result<Vec<User>, ToriiError> {
        // Implementation filters by tenant_id
    }

    /// Create a session for a user in this tenant
    pub async fn create_session(
        &self,
        user: &User,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<Session, ToriiError> {
        // Implementation ensures session is tenant-scoped
    }

    /// Validate a session token within this tenant
    pub async fn validate_session(&self, token: &SessionToken) -> Result<Option<Session>, ToriiError> {
        // Implementation validates tenant context matches
    }

    /// List active sessions for a user in this tenant
    pub async fn list_user_sessions(&self, user_id: &UserId) -> Result<Vec<Session>, ToriiError> {
        // Implementation filters by tenant and user
    }

    /// Revoke a session within this tenant
    pub async fn revoke_session(&self, token: &SessionToken) -> Result<(), ToriiError> {
        // Implementation validates tenant ownership
    }
}

// Tenant-scoped password authentication
pub struct TenantPasswordAuth<'a, R: RepositoryProvider> {
    tenant_scoped: &'a TenantScoped<R>,
}

impl<R: RepositoryProvider> TenantPasswordAuth<'_, R> {
    /// Register a user with password in this tenant
    pub async fn register(
        &self,
        email: &str,
        password: &str,
        name: Option<String>,
    ) -> Result<User, ToriiError> {
        // Implementation creates user with tenant association
    }

    /// Authenticate user with password in this tenant
    pub async fn authenticate(
        &self,
        email: &str,
        password: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        // Implementation scopes authentication to tenant
    }

    /// Change user password in this tenant
    pub async fn change_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), ToriiError> {
        // Implementation validates user belongs to tenant
    }

    /// Reset user password in this tenant
    pub async fn reset_password(
        &self,
        email: &str,
    ) -> Result<SecureToken, ToriiError> {
        // Implementation scopes to tenant
    }
}

// Tenant-scoped OAuth authentication
pub struct TenantOAuthAuth<'a, R: RepositoryProvider> {
    tenant_scoped: &'a TenantScoped<R>,
}

impl<R: RepositoryProvider> TenantOAuthAuth<'_, R> {
    /// Find user by OAuth provider account in this tenant
    pub async fn find_by_provider_account(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, ToriiError> {
        // Implementation scopes query to tenant
    }

    /// Link OAuth account to user in this tenant
    pub async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), ToriiError> {
        // Implementation validates user belongs to tenant
    }

    /// Authenticate with OAuth in this tenant
    pub async fn authenticate(
        &self,
        provider: &str,
        subject: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        // Implementation creates/finds user in tenant context
    }
}

// Tenant-scoped passkey authentication
pub struct TenantPasskeyAuth<'a, R: RepositoryProvider> {
    tenant_scoped: &'a TenantScoped<R>,
}

impl<R: RepositoryProvider> TenantPasskeyAuth<'_, R> {
    /// Register passkey credential for user in this tenant
    pub async fn register_credential(
        &self,
        user_id: &UserId,
        credential: PasskeyCredential,
    ) -> Result<(), ToriiError> {
        // Implementation validates user belongs to tenant
    }

    /// Authenticate with passkey in this tenant
    pub async fn authenticate(
        &self,
        credential_id: &[u8],
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        // Implementation scopes credential lookup to tenant
    }

    /// List passkey credentials for user in this tenant
    pub async fn list_user_credentials(&self, user_id: &UserId) -> Result<Vec<PasskeyCredential>, ToriiError> {
        // Implementation filters by tenant and user
    }
}

// Tenant-scoped magic link authentication
pub struct TenantMagicLinkAuth<'a, R: RepositoryProvider> {
    tenant_scoped: &'a TenantScoped<R>,
}

impl<R: RepositoryProvider> TenantMagicLinkAuth<'_, R> {
    /// Generate magic link token for email in this tenant
    pub async fn generate_token(&self, email: &str) -> Result<SecureToken, ToriiError> {
        // Implementation creates tenant-scoped token
    }

    /// Authenticate with magic link token in this tenant
    pub async fn authenticate(
        &self,
        token: &str,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<(User, Session), ToriiError> {
        // Implementation validates token belongs to tenant
    }
}

// Extension to main Torii interface
impl<R: RepositoryProvider> Torii<R> {
    /// Create tenant-scoped interface
    pub fn with_tenant(&self, tenant_id: impl Into<TenantId>) -> TenantScoped<R> {
        TenantScoped {
            torii: Arc::new(self.clone()),
            tenant_context: TenantContext::new(tenant_id.into()),
        }
    }
}

// Error extensions for tenant operations
#[derive(thiserror::Error, Debug)]
pub enum TenantError {
    #[error("Tenant not found: {tenant_id}")]
    TenantNotFound { tenant_id: String },
    
    #[error("Cross-tenant access denied")]
    CrossTenantAccess,
    
    #[error("Invalid tenant identifier: {tenant_id}")]
    InvalidTenantId { tenant_id: String },
    
    #[error("User does not belong to tenant: {tenant_id}")]
    UserNotInTenant { tenant_id: String },
    
    #[error("Session does not belong to tenant: {tenant_id}")]
    SessionNotInTenant { tenant_id: String },
}
