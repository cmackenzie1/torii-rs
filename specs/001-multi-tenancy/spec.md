# Feature Specification: Multi-Tenancy Support

**Feature Branch**: `001-multi-tenancy`
**Created**: 2025-10-17
**Status**: Draft
**Input**: User description: "Implement Multi-Tenancy"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Tenant-Aware API for Library Users (Priority: P1)

A developer using torii-rs wants to build a multi-tenant SaaS application where they can pass a tenant identifier to torii-rs APIs and have all authentication operations automatically scoped to that tenant.

**Why this priority**: This is the core library feature that enables developers to build multi-tenant applications - providing tenant-scoped APIs that handle data isolation automatically.

**Independent Test**: Can be fully tested by using the torii-rs API with different tenant identifiers and verifying that all operations (user creation, authentication, session management) are properly isolated by tenant.

**Acceptance Scenarios**:

1. **Given** a developer calls `torii.with_tenant("acme-corp").register_user("john@example.com", "password")`, **When** the user is created, **Then** the user should only be accessible when using the "acme-corp" tenant context
2. **Given** users with the same email exist in different tenants, **When** calling `torii.with_tenant("acme-corp").authenticate("john@example.com", "password")`, **Then** only the user from the "acme-corp" tenant should be authenticated
3. **Given** a session created in tenant "acme-corp", **When** validating the session with `torii.with_tenant("beta-inc").validate_session(token)`, **Then** the session should be invalid

---

### User Story 2 - Tenant-Scoped Repository Operations (Priority: P2)

A developer using torii-rs wants all repository operations (user queries, session lookups, etc.) to automatically filter by tenant when using tenant-scoped APIs, without having to manually add tenant filters to every query.

**Why this priority**: Essential for data isolation - the library must handle tenant filtering automatically to prevent developers from accidentally creating cross-tenant data leaks.

**Independent Test**: Can be tested by creating data in multiple tenants and verifying that tenant-scoped repository operations only return data for the specified tenant.

**Acceptance Scenarios**:

1. **Given** users exist in multiple tenants, **When** calling `torii.with_tenant("acme-corp").list_users()`, **Then** only users belonging to "acme-corp" should be returned
2. **Given** a user ID from tenant "beta-inc", **When** calling `torii.with_tenant("acme-corp").get_user(user_id)`, **Then** the library should return None/NotFound
3. **Given** a tenant context, **When** creating any new entity (user, session, etc.), **Then** it should automatically be associated with the current tenant

---

### User Story 3 - Tenant-Scoped Session APIs (Priority: P3)

A developer using torii-rs wants session creation and validation APIs that automatically include tenant context, ensuring sessions are only valid within their originating tenant.

**Why this priority**: Critical for security to prevent session hijacking across tenants, and must be built into the library's session management APIs.

**Independent Test**: Can be tested by creating sessions with tenant context and verifying that session validation APIs respect tenant boundaries.

**Acceptance Scenarios**:

1. **Given** a session created with `torii.with_tenant("acme-corp").create_session(user)`, **When** validating with `torii.with_tenant("beta-inc").validate_session(token)`, **Then** the validation should fail
2. **Given** a user with sessions in multiple tenants, **When** calling `torii.with_tenant("acme-corp").list_user_sessions(user_id)`, **Then** only sessions for the "acme-corp" tenant should be returned

---

### User Story 4 - Tenant-Scoped OAuth APIs (Priority: P4)

A developer using torii-rs wants OAuth authentication APIs that automatically scope OAuth account linking and authentication to the specified tenant context.

**Why this priority**: OAuth is a common authentication method that must work correctly in multi-tenant library usage, ensuring OAuth accounts are properly isolated by tenant in the library's data model.

**Independent Test**: Can be tested by using OAuth APIs with different tenant contexts and verifying OAuth accounts are tenant-scoped in the library's storage.

**Acceptance Scenarios**:

1. **Given** calling `torii.with_tenant("acme-corp").oauth().authenticate(oauth_response)`, **When** the OAuth account is linked, **Then** it should be stored with "acme-corp" tenant association
2. **Given** the same OAuth provider account, **When** authenticating in different tenants via the API, **Then** separate user records should be created in each tenant's scope
3. **Given** an OAuth account linked in tenant "acme-corp", **When** calling `torii.with_tenant("beta-inc").oauth().find_by_provider_account(provider, subject)`, **Then** the library should return None

---

### User Story 5 - Tenant-Scoped Passkey APIs (Priority: P4)

A developer using torii-rs wants passkey/WebAuthn APIs that automatically scope passkey credential registration and authentication to the specified tenant context.

**Why this priority**: Passkey authentication is becoming increasingly important and the library must maintain tenant isolation for passkey credentials in its storage and APIs.

**Independent Test**: Can be tested by using passkey APIs with different tenant contexts and verifying passkey credentials are tenant-scoped in the library's storage.

**Acceptance Scenarios**:

1. **Given** calling `torii.with_tenant("acme-corp").passkey().register_credential(user, credential)`, **When** the passkey is stored, **Then** it should only be accessible via "acme-corp" tenant APIs
2. **Given** a passkey credential from tenant "acme-corp", **When** calling `torii.with_tenant("beta-inc").passkey().authenticate(credential_id)`, **Then** the library should return None/authentication failure
3. **Given** the same credential ID used across tenants, **When** registering via different tenant APIs, **Then** separate passkey records should be created for each tenant

---

### User Story 6 - Tenant-Scoped Magic Link APIs (Priority: P4)

A developer using torii-rs wants magic link APIs that automatically scope token generation and authentication to the specified tenant context.

**Why this priority**: Magic link authentication must maintain tenant isolation in the library's token management and the APIs must prevent cross-tenant token usage.

**Independent Test**: Can be tested by using magic link APIs with different tenant contexts and verifying tokens are tenant-scoped in the library's storage and validation.

**Acceptance Scenarios**:

1. **Given** calling `torii.with_tenant("acme-corp").magic_link().generate_token(email)`, **When** the token is created, **Then** it should only be valid when used with "acme-corp" tenant APIs
2. **Given** a magic link token from tenant "acme-corp", **When** calling `torii.with_tenant("beta-inc").magic_link().authenticate(token)`, **Then** the library should return authentication failure
3. **Given** the same email address exists in multiple tenants, **When** generating tokens via different tenant APIs, **Then** separate tenant-scoped tokens should be created

---

### User Story 7 - Backward Compatibility for Single-Tenant Usage (Priority: P5)

A developer currently using torii-rs in single-tenant mode wants to continue using the existing APIs without any changes, while having the option to migrate to multi-tenant APIs when needed.

**Why this priority**: Essential for adoption - existing users must not be forced to change their code when upgrading to a version with multi-tenancy support.

**Independent Test**: Can be tested by running existing single-tenant code against the new multi-tenant-capable library and verifying all functionality works unchanged.

**Acceptance Scenarios**:

1. **Given** existing code using `torii.register_user(email, password)`, **When** running against the multi-tenant library, **Then** the code should work unchanged (using a default tenant internally)
2. **Given** existing session validation code, **When** running against the multi-tenant library, **Then** sessions should validate correctly without requiring tenant context
3. **Given** a developer wants to migrate to multi-tenancy, **When** they start using `torii.with_tenant(id)` APIs, **Then** they should be able to migrate incrementally without breaking existing functionality

---

### User Story 8 - Database Schema Extensions for Multi-Tenancy (Priority: P6)

A developer using torii-rs wants the library to provide database migration tools that add tenant support to existing single-tenant databases without data loss.

**Why this priority**: Important for existing users who want to migrate to multi-tenancy, but not critical for new multi-tenant deployments.

**Independent Test**: Can be tested by running migration tools on a single-tenant database and verifying all existing data is preserved and accessible via the default tenant.

**Acceptance Scenarios**:

1. **Given** an existing single-tenant database with users and sessions, **When** running the multi-tenancy migration, **Then** all existing data should be associated with a default tenant
2. **Given** a migrated database, **When** using legacy single-tenant APIs, **Then** all existing functionality should work unchanged
3. **Given** a migrated database, **When** using new multi-tenant APIs with the default tenant, **Then** all existing data should be accessible

### Edge Cases

- What happens when a tenant identifier is empty or contains invalid characters in library APIs?
- How does the library handle database migration failures when adding tenant columns to existing tables?
- What occurs when legacy single-tenant APIs are mixed with multi-tenant APIs in the same application?
- How does the library handle database constraints when the same email exists across multiple tenants?
- What happens when session tokens created before multi-tenancy migration are validated?
- How does the library handle repository operations when tenant context is missing from the API call?
- What occurs when the default tenant identifier conflicts with an explicitly created tenant?
- How are database indexes optimized when tenant_id columns are added to existing tables?
- What happens when OAuth state parameters don't include tenant context during callback processing?
- How does the library handle passkey credential lookups when credential IDs are not globally unique?
- What occurs when magic link tokens are generated with one tenant context but validated with another?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Library MUST provide a `with_tenant(tenant_id)` API that returns a tenant-scoped interface for all authentication operations
- **FR-002**: Library MUST automatically filter all repository queries by tenant when using tenant-scoped APIs
- **FR-003**: Library MUST store tenant association with all entities (users, sessions, OAuth accounts, passkeys, magic links)
- **FR-004**: Library MUST prevent cross-tenant data access through tenant-scoped repository implementations
- **FR-005**: Library MUST support multiple users with the same email address across different tenants in its data model
- **FR-006**: Library MUST provide tenant-scoped session creation and validation APIs
- **FR-007**: Library MUST include tenant context in session tokens to prevent cross-tenant session usage
- **FR-008**: Library MUST provide tenant-scoped OAuth authentication APIs that isolate OAuth accounts by tenant
- **FR-009**: Library MUST provide tenant-scoped passkey APIs that isolate WebAuthn credentials by tenant
- **FR-010**: Library MUST provide tenant-scoped magic link APIs that isolate tokens by tenant
- **FR-011**: Library MUST maintain backward compatibility with existing single-tenant APIs (no breaking changes)
- **FR-012**: Library MUST provide database migration tools to add multi-tenancy to existing single-tenant databases
- **FR-013**: Library MUST use a default tenant for legacy single-tenant API calls to maintain compatibility
- **FR-014**: Library MUST extend all storage backends (SQLite, PostgreSQL, MySQL) to support tenant columns
- **FR-015**: Library MUST provide tenant-aware repository traits that automatically handle tenant filtering
- **FR-016**: Library MUST validate tenant identifiers are non-empty strings when provided to APIs
- **FR-017**: Library MUST support tenant-scoped user lookup operations (by email, by ID) that respect tenant boundaries
- **FR-018**: Library MUST provide consistent tenant-scoped APIs across all authentication methods (password, OAuth, passkey, magic link)

### Key Entities

- **TenantId**: A newtype wrapper around String that represents a tenant identifier in the library's type system
- **TenantContext**: A context object that carries tenant information through the library's API calls and repository operations
- **TenantScoped<T>**: A wrapper type that associates any entity with a tenant, used internally by the library
- **User (Extended)**: The existing User entity extended with an optional tenant_id field for multi-tenant storage
- **Session (Extended)**: The existing Session entity extended with a tenant_id field to scope sessions by tenant
- **OAuthAccount (Extended)**: The existing OAuthAccount entity extended with a tenant_id field for tenant-scoped OAuth linking
- **PasskeyCredential (Extended)**: The existing passkey entities extended with tenant_id fields for tenant-scoped WebAuthn
- **MagicLinkToken (Extended)**: The existing magic link entities extended with tenant_id fields for tenant-scoped tokens

### Database-Specific Implementation Requirements

#### PostgreSQL Implementation (torii-storage-postgres)
- **PG-001**: MUST use PostgreSQL-specific features for optimal performance (partial indexes, JSONB for metadata)
- **PG-002**: MUST implement tenant_id filtering using PostgreSQL's row-level security (RLS) where applicable
- **PG-003**: MUST use PostgreSQL's UPSERT capabilities for efficient tenant-scoped operations
- **PG-004**: MUST leverage PostgreSQL's advanced indexing (GIN, GIST) for tenant-scoped queries
- **PG-005**: MUST support PostgreSQL connection pooling with tenant-aware connection management
- **PG-006**: MUST implement PostgreSQL-specific migration scripts with proper transaction handling

#### MySQL Implementation (torii-storage-seaorm)
- **MY-001**: MUST support MySQL 8.0+ features including JSON columns for flexible metadata storage
- **MY-002**: MUST implement tenant_id filtering with MySQL's optimized composite indexes
- **MY-003**: MUST use MySQL's INSERT ... ON DUPLICATE KEY UPDATE for tenant-scoped upsert operations
- **MY-004**: MUST leverage MySQL's generated columns for computed tenant-scoped values where beneficial
- **MY-005**: MUST support MySQL connection pooling with proper tenant isolation
- **MY-006**: MUST implement MySQL-specific migration scripts with proper foreign key handling
- **MY-007**: MUST ensure compatibility with both MySQL and MariaDB through SeaORM abstractions

#### SeaORM Multi-Database Support
- **ORM-001**: MUST provide database-agnostic tenant-scoped repository implementations
- **ORM-002**: MUST handle database-specific SQL generation for optimal tenant filtering
- **ORM-003**: MUST support migration generation for all supported databases (SQLite, PostgreSQL, MySQL)
- **ORM-004**: MUST provide consistent error handling across different database backends
- **ORM-005**: MUST optimize query generation for tenant-scoped operations across all databases

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Library APIs provide 100% data isolation - tenant-scoped queries never return data from other tenants
- **SC-002**: Library supports at least 1000 concurrent tenants without performance degradation in repository operations
- **SC-003**: Zero cross-tenant data leakage in library test scenarios across all authentication methods
- **SC-004**: 100% backward compatibility - existing single-tenant code works unchanged with the multi-tenant library
- **SC-005**: Multi-tenant API calls complete within 10% of single-tenant API call times
- **SC-006**: Library data model supports duplicate email addresses across tenants with unique constraints per tenant
- **SC-007**: Tenant-scoped session validation APIs complete in under 50ms for active sessions
- **SC-008**: Database schema changes for multi-tenancy add less than 10% storage overhead
- **SC-009**: All authentication method APIs (password, OAuth, passkey, magic link) maintain tenant isolation with 100% accuracy
- **SC-010**: Library migration tools successfully convert 100% of single-tenant databases to multi-tenant without data loss
- **SC-011**: Tenant-scoped APIs prevent cross-tenant access with 100% accuracy in security testing
- **SC-012**: Library provides consistent tenant-scoped APIs across all storage backends (SQLite, PostgreSQL, MySQL)
- **SC-013**: PostgreSQL implementation leverages database-specific optimizations (RLS, JSONB, advanced indexes) for tenant operations
- **SC-014**: MySQL implementation supports both MySQL 8.0+ and MariaDB with optimal performance for tenant-scoped queries
- **SC-015**: SeaORM implementation provides consistent behavior across SQLite, PostgreSQL, and MySQL with <5% performance variance

## Assumptions

- Tenant identifiers will be provided by library users as string values and the library will treat them as opaque identifiers
- The library will support hundreds to thousands of tenants per database without requiring sharding
- Tenant creation and deletion will be handled by library users; the library only needs to support tenant-scoped operations
- Applications using the library will provide tenant context when calling multi-tenant APIs
- Database performance will remain acceptable with additional tenant_id columns and indexes
- Existing storage backends (SQLite, PostgreSQL, MySQL) can be extended with tenant columns without breaking schema compatibility
- The library will use a default tenant identifier for backward compatibility with single-tenant APIs
- Migration tools will be provided as part of the library to help users upgrade existing databases
- The library will not enforce tenant-specific authentication policies; that remains an application concern
- Session token formats can be extended to include tenant context without breaking existing token validation
- The library's repository traits can be extended to support tenant filtering without breaking existing implementations

