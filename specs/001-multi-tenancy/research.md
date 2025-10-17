# Multi-Tenancy Research

**Date**: 2025-10-17  
**Feature**: Multi-Tenancy Support for torii-rs  
**Purpose**: Resolve technical unknowns and establish implementation patterns

## Research Tasks Completed

### 1. Tenant Context Propagation Patterns

**Decision**: Use a `TenantContext` wrapper that provides tenant-scoped interfaces

**Rationale**: 
- Provides compile-time safety for tenant operations
- Maintains backward compatibility with existing APIs
- Follows Rust ownership patterns for context propagation
- Enables clear separation between single-tenant and multi-tenant operations

**Alternatives considered**:
- Thread-local storage: Rejected due to async context issues
- Parameter passing: Rejected due to API verbosity and breaking changes
- Middleware pattern: Rejected due to complexity and unclear ownership

**Implementation Pattern**:
```rust
// New tenant-scoped API
let tenant_torii = torii.with_tenant("acme-corp");
let user = tenant_torii.register_user("user@example.com", "password").await?;

// Existing API continues to work (uses default tenant internally)
let user = torii.register_user("user@example.com", "password").await?;
```

### 2. Database Schema Migration Strategy

**Decision**: Add nullable `tenant_id` columns with default values for backward compatibility

**Rationale**:
- Non-destructive migrations preserve existing data
- Nullable columns allow gradual migration
- Default tenant value maintains single-tenant behavior
- Indexes can be added incrementally for performance

**Alternatives considered**:
- Separate tenant tables: Rejected due to complexity and query performance
- Schema-per-tenant: Rejected due to connection pooling and maintenance overhead
- Tenant prefix in primary keys: Rejected due to breaking changes to existing IDs

**Migration Strategy**:
1. Add nullable `tenant_id` columns to all tables
2. Set default value for existing records
3. Add indexes on `tenant_id` columns
4. Update queries to filter by tenant
5. Make `tenant_id` non-nullable in future major version

### 3. Session Token Tenant Scoping

**Decision**: Include tenant context in session metadata without breaking existing token formats

**Rationale**:
- JWT tokens can include tenant claim without breaking validation
- Opaque tokens can store tenant association in database
- Existing session validation continues to work
- Tenant validation happens at API boundary

**Alternatives considered**:
- Tenant-prefixed tokens: Rejected due to breaking changes
- Separate session tables per tenant: Rejected due to complexity
- Token encryption with tenant: Rejected due to performance overhead

**Implementation Pattern**:
```rust
// JWT: Add "tenant" claim to token payload
// Opaque: Store tenant_id in sessions table, validate on lookup
```

### 4. Repository Trait Extensions

**Decision**: Extend existing repository traits with tenant-aware methods while maintaining backward compatibility

**Rationale**:
- Preserves existing repository implementations
- Allows gradual adoption of tenant-aware operations
- Maintains type safety through trait bounds
- Enables automatic tenant filtering in implementations

**Alternatives considered**:
- New tenant-specific repository traits: Rejected due to code duplication
- Generic tenant parameter: Rejected due to complexity and breaking changes
- Runtime tenant injection: Rejected due to lack of compile-time safety

**Implementation Pattern**:
```rust
// Existing trait methods continue to work (use default tenant)
// New tenant-scoped methods added to same traits
pub trait UserRepository {
    async fn create_user(&self, email: &str) -> Result<User, Error>; // existing
    async fn create_user_in_tenant(&self, tenant_id: &TenantId, email: &str) -> Result<User, Error>; // new
}
```

### 5. Error Handling for Tenant Operations

**Decision**: Extend existing error types with tenant-specific variants

**Rationale**:
- Maintains existing error handling patterns
- Provides clear error messages for tenant-related issues
- Enables proper error propagation through service layers
- Follows thiserror patterns used throughout the project

**Implementation Pattern**:
```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    // Existing variants...
    #[error("Tenant not found: {tenant_id}")]
    TenantNotFound { tenant_id: String },
    #[error("Cross-tenant access denied")]
    CrossTenantAccess,
}
```

### 6. Performance Optimization Strategies

**Decision**: Use composite indexes and query optimization for tenant-scoped operations

**Rationale**:
- Composite indexes (tenant_id, other_columns) provide optimal query performance
- Query planners can efficiently filter by tenant first
- Minimal overhead for single-tenant deployments
- Scales well with increasing tenant count

**Database Index Strategy**:
- `(tenant_id, email)` for user lookups
- `(tenant_id, token)` for session validation
- `(tenant_id, user_id)` for user-related queries
- `(tenant_id, created_at)` for time-based queries

## Implementation Readiness

All technical unknowns have been resolved. The research establishes clear patterns for:
- ✅ Tenant context propagation through wrapper APIs
- ✅ Non-destructive database schema migrations
- ✅ Session token tenant scoping strategies
- ✅ Repository trait extensions for tenant awareness
- ✅ Error handling for tenant-specific operations
- ✅ Performance optimization through indexing strategies

Ready to proceed to Phase 1: Design & Contracts.
