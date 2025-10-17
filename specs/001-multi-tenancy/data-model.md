# Multi-Tenancy Data Model

**Date**: 2025-10-17  
**Feature**: Multi-Tenancy Support for torii-rs  
**Purpose**: Define data structures and relationships for tenant-scoped authentication

## Core Types

### TenantId
```rust
/// Strongly-typed tenant identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: impl Into<String>) -> Self { /* validation */ }
    pub fn default_tenant() -> Self { /* returns "default" */ }
    pub fn as_str(&self) -> &str { &self.0 }
}
```

**Validation Rules**:
- Non-empty string
- ASCII alphanumeric plus hyphens and underscores
- Maximum 64 characters
- Case-sensitive

### TenantContext
```rust
/// Runtime context for tenant-scoped operations
#[derive(Debug, Clone)]
pub struct TenantContext {
    tenant_id: TenantId,
}

impl TenantContext {
    pub fn new(tenant_id: TenantId) -> Self { /* */ }
    pub fn tenant_id(&self) -> &TenantId { &self.tenant_id }
}
```

## Extended Entity Models

### User (Extended)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: UserId,
    pub tenant_id: TenantId,           // NEW: Tenant association
    pub email: String,
    pub name: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**Constraints**:
- Unique (tenant_id, email) - same email allowed across tenants
- tenant_id is required for all new users
- Existing users get default tenant during migration

### Session (Extended)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub token: SessionToken,
    pub user_id: UserId,
    pub tenant_id: TenantId,           // NEW: Tenant association
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
```

**Constraints**:
- tenant_id must match the user's tenant_id
- Session tokens are globally unique
- Validation requires tenant context match

### OAuthAccount (Extended)
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub id: i64,
    pub user_id: UserId,
    pub tenant_id: TenantId,           // NEW: Tenant association
    pub provider: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**Constraints**:
- Unique (tenant_id, provider, subject) - same OAuth account can exist across tenants
- tenant_id must match the user's tenant_id

### PasskeyCredential (Extended)
```rust
#[derive(Debug, Clone)]
pub struct PasskeyCredential {
    pub id: i64,
    pub user_id: UserId,
    pub tenant_id: TenantId,           // NEW: Tenant association
    pub credential_id: String,
    pub data_json: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**Constraints**:
- Unique (tenant_id, credential_id) - same credential ID can exist across tenants
- tenant_id must match the user's tenant_id

### MagicLinkToken (Extended)
```rust
#[derive(Debug, Clone)]
pub struct MagicLinkToken {
    pub id: i64,
    pub user_id: Option<UserId>,
    pub tenant_id: TenantId,           // NEW: Tenant association
    pub token: String,
    pub purpose: TokenPurpose,
    pub used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**Constraints**:
- tenant_id required for all tokens
- Token validation requires tenant context match

## Database Schema Changes

### Migration Strategy
1. **Phase 1**: Add nullable `tenant_id` columns
2. **Phase 2**: Populate default tenant for existing records
3. **Phase 3**: Add indexes for performance
4. **Phase 4**: Update application code to use tenant-aware APIs

### Database-Specific Considerations

#### PostgreSQL-Specific Features
- **Row-Level Security (RLS)**: Optional tenant isolation at database level
- **JSONB Columns**: Store tenant-specific metadata efficiently
- **Partial Indexes**: Optimize queries for active tenants only
- **Generated Columns**: Computed tenant-scoped identifiers
- **Advanced Constraints**: Check constraints for tenant validation

#### MySQL-Specific Features
- **JSON Columns**: Store tenant-specific configuration and metadata
- **Generated Columns**: Computed tenant-scoped values for indexing
- **Composite Indexes**: Optimized (tenant_id, entity_id) indexes
- **Foreign Key Constraints**: Proper cascade behavior for tenant data
- **Partitioning**: Optional tenant-based table partitioning for large datasets

### Table Modifications

#### users table

**Generic SQL (SQLite/Basic)**:
```sql
-- Add tenant_id column (nullable initially)
ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64);

-- Set default tenant for existing records
UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add composite unique constraint
CREATE UNIQUE INDEX idx_users_tenant_email ON users(tenant_id, email);

-- Add tenant index
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
```

**PostgreSQL-Specific Optimizations**:
```sql
-- Add tenant_id column with constraint
ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64)
  CONSTRAINT chk_tenant_id_format CHECK (tenant_id ~ '^[a-zA-Z0-9_-]+$');

-- Set default tenant for existing records
UPDATE users SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add optimized composite unique constraint
CREATE UNIQUE INDEX CONCURRENTLY idx_users_tenant_email ON users(tenant_id, email);

-- Add partial index for active tenants (optional optimization)
CREATE INDEX CONCURRENTLY idx_users_active_tenant ON users(tenant_id)
  WHERE tenant_id != 'archived';

-- Optional: Enable row-level security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
```

**MySQL-Specific Optimizations**:
```sql
-- Add tenant_id column with constraint
ALTER TABLE users ADD COLUMN tenant_id VARCHAR(64) NOT NULL DEFAULT 'default'
  CHECK (tenant_id REGEXP '^[a-zA-Z0-9_-]+$');

-- Add optimized composite unique constraint
ALTER TABLE users ADD UNIQUE KEY idx_users_tenant_email (tenant_id, email);

-- Add tenant index with prefix optimization
ALTER TABLE users ADD INDEX idx_users_tenant_id (tenant_id(32));

-- Optional: Add JSON column for tenant-specific metadata
ALTER TABLE users ADD COLUMN tenant_metadata JSON DEFAULT NULL;
```

#### sessions table
```sql
-- Add tenant_id column
ALTER TABLE sessions ADD COLUMN tenant_id VARCHAR(64);

-- Set default tenant for existing records
UPDATE sessions SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add composite indexes
CREATE INDEX idx_sessions_tenant_token ON sessions(tenant_id, token);
CREATE INDEX idx_sessions_tenant_user ON sessions(tenant_id, user_id);
```

#### oauth_accounts table
```sql
-- Add tenant_id column
ALTER TABLE oauth_accounts ADD COLUMN tenant_id VARCHAR(64);

-- Set default tenant for existing records
UPDATE oauth_accounts SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add composite unique constraint
CREATE UNIQUE INDEX idx_oauth_tenant_provider_subject ON oauth_accounts(tenant_id, provider, subject);
```

#### passkeys table
```sql
-- Add tenant_id column
ALTER TABLE passkeys ADD COLUMN tenant_id VARCHAR(64);

-- Set default tenant for existing records
UPDATE passkeys SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add composite unique constraint
CREATE UNIQUE INDEX idx_passkeys_tenant_credential ON passkeys(tenant_id, credential_id);
```

#### secure_tokens table (magic links)
```sql
-- Add tenant_id column
ALTER TABLE secure_tokens ADD COLUMN tenant_id VARCHAR(64);

-- Set default tenant for existing records
UPDATE secure_tokens SET tenant_id = 'default' WHERE tenant_id IS NULL;

-- Add tenant index
CREATE INDEX idx_secure_tokens_tenant_id ON secure_tokens(tenant_id);
```

## Relationships

### Tenant Isolation Rules
1. **User → Tenant**: Each user belongs to exactly one tenant
2. **Session → Tenant**: Each session is scoped to the user's tenant
3. **OAuthAccount → Tenant**: Each OAuth account is scoped to the user's tenant
4. **PasskeyCredential → Tenant**: Each passkey is scoped to the user's tenant
5. **MagicLinkToken → Tenant**: Each token is scoped to a specific tenant

### Cross-Tenant Constraints
- Users cannot access data from other tenants
- Sessions are invalid across tenant boundaries
- OAuth accounts are isolated by tenant
- Passkey credentials are isolated by tenant
- Magic link tokens are isolated by tenant

## State Transitions

### User Creation
```
1. Validate tenant_id exists (application responsibility)
2. Check email uniqueness within tenant
3. Create user with tenant association
4. All related entities inherit tenant context
```

### Session Creation
```
1. User authenticates within tenant context
2. Session created with user's tenant_id
3. Session token includes tenant metadata
4. Validation requires tenant context match
```

### Cross-Tenant Operations
```
1. User migration between tenants (admin operation)
2. Tenant data export/import (admin operation)
3. Tenant deletion with cascade cleanup (admin operation)
```

## Validation Rules

### Tenant Context Validation
- All operations must include valid tenant context
- Tenant context must match entity tenant associations
- Cross-tenant access attempts result in access denied errors

### Data Integrity
- Foreign key relationships respect tenant boundaries
- Unique constraints are tenant-scoped where appropriate
- Cascade operations respect tenant isolation

### Performance Considerations
- Composite indexes optimize tenant-scoped queries
- Query patterns filter by tenant_id first
- Connection pooling remains tenant-agnostic
