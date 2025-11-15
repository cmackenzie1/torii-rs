//! Tenant-related types and utilities for multi-tenancy support.
//!
//! This module provides the core types for tenant identification and context
//! management in the torii-rs authentication library.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Strongly-typed tenant identifier.
///
/// A `TenantId` represents a unique identifier for a tenant in a multi-tenant
/// authentication system. It enforces validation rules to ensure tenant IDs
/// are well-formed and safe to use in database queries and API operations.
///
/// # Validation Rules
/// - Non-empty string
/// - ASCII alphanumeric characters plus hyphens and underscores only
/// - Maximum 64 characters
/// - Case-sensitive
///
/// # Examples
///
/// ```rust
/// use torii_core::tenant::TenantId;
///
/// // Create a new tenant ID
/// let tenant_id = TenantId::new("acme-corp").unwrap();
/// assert_eq!(tenant_id.as_str(), "acme-corp");
///
/// // Use the default tenant
/// let default_tenant = TenantId::default_tenant();
/// assert_eq!(default_tenant.as_str(), "default");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    /// Creates a new `TenantId` with validation.
    ///
    /// # Arguments
    /// * `id` - The tenant identifier string
    ///
    /// # Returns
    /// * `Ok(TenantId)` if the ID is valid
    /// * `Err(TenantError)` if the ID fails validation
    ///
    /// # Errors
    /// Returns `TenantError::InvalidTenantId` if:
    /// - The ID is empty
    /// - The ID contains invalid characters
    /// - The ID exceeds 64 characters
    pub fn new(id: impl Into<String>) -> Result<Self, TenantError> {
        let id = id.into();
        Self::validate_tenant_id(&id)?;
        Ok(TenantId(id))
    }

    /// Creates a new `TenantId` without validation.
    ///
    /// # Safety
    /// This method bypasses validation and should only be used when the
    /// tenant ID is known to be valid (e.g., from trusted database sources).
    ///
    /// # Arguments
    /// * `id` - The tenant identifier string
    pub fn new_unchecked(id: impl Into<String>) -> Self {
        TenantId(id.into())
    }

    /// Returns the default tenant identifier.
    ///
    /// The default tenant is used for backward compatibility with existing
    /// single-tenant deployments and legacy API calls.
    pub fn default_tenant() -> Self {
        TenantId("default".to_string())
    }

    /// Returns the tenant ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validates a tenant ID string according to the rules.
    fn validate_tenant_id(id: &str) -> Result<(), TenantError> {
        if id.is_empty() {
            return Err(TenantError::InvalidTenantId {
                id: id.to_string(),
                reason: "Tenant ID cannot be empty".to_string(),
            });
        }

        if id.len() > 64 {
            return Err(TenantError::InvalidTenantId {
                id: id.to_string(),
                reason: "Tenant ID cannot exceed 64 characters".to_string(),
            });
        }

        // Check for valid characters: ASCII alphanumeric, hyphens, and underscores
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(TenantError::InvalidTenantId {
                id: id.to_string(),
                reason: "Tenant ID can only contain ASCII alphanumeric characters, hyphens, and underscores".to_string(),
            });
        }

        Ok(())
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for TenantId {
    fn from(id: &str) -> Self {
        TenantId::new(id).expect("Invalid tenant ID")
    }
}

impl AsRef<str> for TenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Runtime context for tenant-scoped operations.
///
/// `TenantContext` carries tenant information through the authentication
/// library's API calls and repository operations, ensuring that all
/// operations are properly scoped to the correct tenant.
///
/// # Examples
///
/// ```rust
/// use torii_core::tenant::{TenantId, TenantContext};
///
/// let tenant_id = TenantId::new("acme-corp").unwrap();
/// let context = TenantContext::new(tenant_id);
/// assert_eq!(context.tenant_id().as_str(), "acme-corp");
/// ```
#[derive(Debug, Clone)]
pub struct TenantContext {
    tenant_id: TenantId,
}

impl TenantContext {
    /// Creates a new tenant context.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant identifier for this context
    pub fn new(tenant_id: TenantId) -> Self {
        TenantContext { tenant_id }
    }

    /// Creates a tenant context for the default tenant.
    pub fn default_tenant() -> Self {
        TenantContext {
            tenant_id: TenantId::default_tenant(),
        }
    }

    /// Returns a reference to the tenant ID.
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// Returns true if this context represents the default tenant.
    pub fn is_default_tenant(&self) -> bool {
        self.tenant_id == TenantId::default_tenant()
    }
}

/// Errors related to tenant operations.
#[derive(Debug, thiserror::Error)]
pub enum TenantError {
    /// Invalid tenant identifier.
    #[error("Invalid tenant ID '{id}': {reason}")]
    InvalidTenantId { id: String, reason: String },

    /// Tenant not found.
    #[error("Tenant '{id}' not found")]
    TenantNotFound { id: String },

    /// Cross-tenant access attempt.
    #[error("Access denied: operation attempted across tenant boundaries")]
    CrossTenantAccess,

    /// Missing tenant context.
    #[error("Tenant context is required for this operation")]
    MissingTenantContext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_id_validation() {
        // Valid tenant IDs
        assert!(TenantId::new("valid-tenant").is_ok());
        assert!(TenantId::new("tenant_123").is_ok());
        assert!(TenantId::new("TENANT").is_ok());
        assert!(TenantId::new("a").is_ok());

        // Invalid tenant IDs
        assert!(TenantId::new("").is_err()); // Empty
        assert!(TenantId::new("tenant with spaces").is_err()); // Spaces
        assert!(TenantId::new("tenant@domain").is_err()); // Special chars
        assert!(TenantId::new("tenant.name").is_err()); // Dots
        assert!(TenantId::new("a".repeat(65)).is_err()); // Too long
    }

    #[test]
    fn test_default_tenant() {
        let default_tenant = TenantId::default_tenant();
        assert_eq!(default_tenant.as_str(), "default");
    }

    #[test]
    fn test_tenant_context() {
        let tenant_id = TenantId::new("test-tenant").unwrap();
        let context = TenantContext::new(tenant_id.clone());
        
        assert_eq!(context.tenant_id(), &tenant_id);
        assert!(!context.is_default_tenant());

        let default_context = TenantContext::default_tenant();
        assert!(default_context.is_default_tenant());
    }

    #[test]
    fn test_tenant_id_display() {
        let tenant_id = TenantId::new("test-tenant").unwrap();
        assert_eq!(format!("{}", tenant_id), "test-tenant");
    }

    #[test]
    fn test_tenant_id_serde() {
        let tenant_id = TenantId::new("test-tenant").unwrap();
        let json = serde_json::to_string(&tenant_id).unwrap();
        let deserialized: TenantId = serde_json::from_str(&json).unwrap();
        assert_eq!(tenant_id, deserialized);
    }
}
