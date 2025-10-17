# Tasks: Multi-Tenancy Support

**Input**: Design documents from `/specs/001-multi-tenancy/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: Tests are NOT explicitly requested in the feature specification, so test tasks are omitted.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [x] T001 Create TenantId and TenantContext core types in torii-core/src/tenant.rs
- [x] T002 [P] Add tenant-related error types to torii-core/src/error.rs
- [x] T003 [P] Add serde derives and validation to TenantId in torii-core/src/tenant.rs

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T004 Add tenant_id field to User struct in torii-core/src/user.rs
- [x] T005 [P] Add tenant_id field to Session struct in torii-core/src/session/mod.rs
- [x] T006 [P] Add tenant_id field to OAuthAccount struct in torii-core/src/user.rs
- [x] T007 [P] Extend UserRepository trait with tenant-scoped methods in torii-core/src/repositories/user.rs
- [x] T008 [P] Extend SessionRepository trait with tenant-scoped methods in torii-core/src/repositories/session.rs
- [x] T009 [P] Extend OAuthRepository trait with tenant-scoped methods in torii-core/src/repositories/oauth.rs
- [x] T010 [P] Extend PasskeyRepository trait with tenant-scoped methods in torii-core/src/repositories/passkey.rs
- [x] T011 [P] Extend TokenRepository trait with tenant-scoped methods in torii-core/src/repositories/token.rs
- [x] T012 [P] Extend PasswordRepository trait with tenant-scoped methods in torii-core/src/repositories/password.rs
- [ ] T014 [P] Add PostgreSQL-specific migration with RLS and JSONB support in torii-storage-postgres/src/migrations/add_tenant_columns.rs
- [ ] T015 [P] Add MySQL-specific migration with JSON columns and optimized indexes in torii-storage-seaorm/src/migrations/add_tenant_columns.rs
- [ ] T016 [P] Add PostgreSQL performance optimizations (partial indexes, constraints) in torii-storage-postgres/src/migrations/optimize_tenant_queries.rs
- [ ] T017 [P] Add MySQL performance optimizations (composite indexes, generated columns) in torii-storage-seaorm/src/migrations/optimize_tenant_queries.rs

**Checkpoint**: ✅ Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Tenant-Aware API for Library Users (Priority: P1) 🎯 MVP

**Goal**: Provide `with_tenant(tenant_id)` API that returns tenant-scoped interface for all authentication operations

**Independent Test**: Use torii-rs API with different tenant identifiers and verify operations are properly isolated by tenant

### Implementation for User Story 1

- [ ] T016 [P] [US1] Create TenantScoped wrapper struct in torii/src/tenant.rs
- [ ] T017 [P] [US1] Implement with_tenant() method on main Torii struct in torii/src/lib.rs
- [ ] T018 [US1] Implement tenant-scoped password authentication APIs in torii/src/tenant.rs
- [ ] T019 [US1] Add tenant context validation and error handling in torii/src/tenant.rs
- [ ] T020 [US1] Update main Torii constructor to support default tenant in torii/src/lib.rs
- [ ] T021 [US1] Add integration tests for tenant-scoped user registration in torii/tests/tenant_isolation.rs
- [ ] T022 [US1] Add integration tests for tenant-scoped authentication in torii/tests/tenant_isolation.rs

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Tenant-Scoped Repository Operations (Priority: P2)

**Goal**: All repository operations automatically filter by tenant when using tenant-scoped APIs

**Independent Test**: Create data in multiple tenants and verify tenant-scoped repository operations only return data for specified tenant

### Implementation for User Story 2

- [ ] T023 [P] [US2] Implement tenant-scoped UserRepository methods in torii-storage-sqlite/src/repositories/user.rs
- [ ] T024 [P] [US2] Implement PostgreSQL-optimized tenant-scoped UserRepository with RLS support in torii-storage-postgres/src/repositories/user.rs
- [ ] T025 [P] [US2] Implement MySQL-optimized tenant-scoped UserRepository with composite indexes in torii-storage-seaorm/src/repositories/user.rs
- [ ] T026 [P] [US2] Implement tenant-scoped SessionRepository methods in torii-storage-sqlite/src/repositories/session.rs
- [ ] T027 [P] [US2] Implement PostgreSQL-optimized tenant-scoped SessionRepository with JSONB metadata in torii-storage-postgres/src/repositories/session.rs
- [ ] T028 [P] [US2] Implement MySQL-optimized tenant-scoped SessionRepository with JSON columns in torii-storage-seaorm/src/repositories/session.rs
- [ ] T029 [US2] Update UserService to use tenant-scoped repository methods in torii-core/src/services/user.rs
- [ ] T030 [US2] Add database indexes for tenant_id columns across all storage backends
- [ ] T031 [US2] Add integration tests for tenant-scoped repository filtering in torii/tests/repository_isolation.rs

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Tenant-Scoped Session APIs (Priority: P3)

**Goal**: Session creation and validation APIs automatically include tenant context

**Independent Test**: Create sessions with tenant context and verify session validation APIs respect tenant boundaries

### Implementation for User Story 3

- [ ] T032 [P] [US3] Extend Session struct with tenant validation methods in torii-core/src/session/mod.rs
- [ ] T033 [P] [US3] Update SessionService to handle tenant context in torii-core/src/services/session.rs
- [ ] T034 [P] [US3] Implement tenant-scoped session creation in torii/src/tenant.rs
- [ ] T035 [P] [US3] Implement tenant-scoped session validation in torii/src/tenant.rs
- [ ] T036 [US3] Update JWT session provider to include tenant claims in torii-core/src/session/jwt.rs
- [ ] T037 [US3] Update opaque session provider to validate tenant context in torii-core/src/session/opaque.rs
- [ ] T038 [US3] Add integration tests for cross-tenant session validation in torii/tests/session_isolation.rs

**Checkpoint**: All core session management should now be tenant-aware

---

## Phase 6: User Story 4 - Tenant-Scoped OAuth APIs (Priority: P4)

**Goal**: OAuth authentication APIs automatically scope OAuth account linking and authentication to specified tenant context

**Independent Test**: Use OAuth APIs with different tenant contexts and verify OAuth accounts are tenant-scoped in library storage

### Implementation for User Story 4

- [ ] T039 [P] [US4] Add tenant_id field to OAuthAccount and related structs in torii-core/src/user.rs
- [ ] T040 [P] [US4] Implement tenant-scoped OAuth repository methods in torii-storage-sqlite/src/repositories/oauth.rs
- [ ] T041 [P] [US4] Implement tenant-scoped OAuth repository methods in torii-storage-postgres/src/repositories/oauth.rs
- [ ] T042 [P] [US4] Implement tenant-scoped OAuth repository methods in torii-storage-seaorm/src/repositories/oauth.rs
- [ ] T043 [P] [US4] Implement tenant-scoped OAuth authentication APIs in torii/src/tenant.rs
- [ ] T044 [US4] Update OAuthService to handle tenant context in torii-core/src/services/oauth.rs
- [ ] T045 [US4] Add integration tests for tenant-scoped OAuth account linking in torii/tests/oauth_isolation.rs

**Checkpoint**: OAuth authentication should now be fully tenant-aware

---

## Phase 7: User Story 5 - Tenant-Scoped Passkey APIs (Priority: P4)

**Goal**: Passkey/WebAuthn APIs automatically scope passkey credential registration and authentication to specified tenant context

**Independent Test**: Use passkey APIs with different tenant contexts and verify passkey credentials are tenant-scoped in library storage

### Implementation for User Story 5

- [ ] T046 [P] [US5] Add tenant_id field to PasskeyCredential struct in torii-core/src/passkey/mod.rs
- [ ] T047 [P] [US5] Implement tenant-scoped Passkey repository methods in torii-storage-sqlite/src/repositories/passkey.rs
- [ ] T048 [P] [US5] Implement tenant-scoped Passkey repository methods in torii-storage-postgres/src/repositories/passkey.rs
- [ ] T049 [P] [US5] Implement tenant-scoped Passkey repository methods in torii-storage-seaorm/src/repositories/passkey.rs
- [ ] T050 [P] [US5] Implement tenant-scoped passkey authentication APIs in torii/src/tenant.rs
- [ ] T051 [US5] Update PasskeyService to handle tenant context in torii-core/src/services/passkey.rs
- [ ] T052 [US5] Add integration tests for tenant-scoped passkey credentials in torii/tests/passkey_isolation.rs

**Checkpoint**: Passkey authentication should now be fully tenant-aware

---

## Phase 8: User Story 6 - Tenant-Scoped Magic Link APIs (Priority: P4)

**Goal**: Magic link APIs automatically scope token generation and authentication to specified tenant context

**Independent Test**: Use magic link APIs with different tenant contexts and verify tokens are tenant-scoped in library validation

### Implementation for User Story 6

- [ ] T053 [P] [US6] Add tenant_id field to SecureToken struct in torii-core/src/token.rs
- [ ] T054 [P] [US6] Implement tenant-scoped Token repository methods in torii-storage-sqlite/src/repositories/token.rs
- [ ] T055 [P] [US6] Implement tenant-scoped Token repository methods in torii-storage-postgres/src/repositories/token.rs
- [ ] T056 [P] [US6] Implement tenant-scoped Token repository methods in torii-storage-seaorm/src/repositories/token.rs
- [ ] T057 [P] [US6] Implement tenant-scoped magic link APIs in torii/src/tenant.rs
- [ ] T058 [US6] Update TokenService to handle tenant context in torii-core/src/services/token.rs
- [ ] T059 [US6] Add integration tests for tenant-scoped magic link tokens in torii/tests/magic_link_isolation.rs

**Checkpoint**: Magic link authentication should now be fully tenant-aware

---

## Phase 9: User Story 7 - Backward Compatibility for Single-Tenant Usage (Priority: P5)

**Goal**: Existing single-tenant APIs work unchanged while having option to migrate to multi-tenant APIs

**Independent Test**: Run existing single-tenant code against multi-tenant library and verify all functionality works unchanged

### Implementation for User Story 7

- [ ] T060 [P] [US7] Implement default tenant mechanism in torii-core/src/tenant.rs
- [ ] T061 [P] [US7] Update existing API methods to use default tenant internally in torii/src/lib.rs
- [ ] T062 [P] [US7] Add backward compatibility layer for all authentication methods in torii/src/compat.rs
- [ ] T063 [US7] Update repository implementations to handle None tenant_id as default in all storage backends
- [ ] T064 [US7] Add comprehensive backward compatibility tests in torii/tests/backward_compatibility.rs
- [ ] T065 [US7] Add migration guide and examples in examples/migration/

**Checkpoint**: Existing single-tenant applications should work unchanged

---

## Phase 10: User Story 8 - Database Schema Extensions for Multi-Tenancy (Priority: P6)

**Goal**: Library provides database migration tools that add tenant support to existing single-tenant databases

**Independent Test**: Run migration tools on single-tenant database and verify all existing data is preserved and accessible via default tenant

### Implementation for User Story 8

- [ ] T066 [P] [US8] Create migration utility for SQLite in torii-storage-sqlite/src/migrations/migrate_to_multi_tenant.rs
- [ ] T067 [P] [US8] Create migration utility for PostgreSQL in torii-storage-postgres/src/migrations/migrate_to_multi_tenant.rs
- [ ] T068 [P] [US8] Create migration utility for SeaORM in torii-storage-seaorm/src/migrations/migrate_to_multi_tenant.rs
- [ ] T069 [US8] Add migration CLI tool in torii/src/bin/migrate.rs
- [ ] T070 [US8] Add migration validation and rollback capabilities across all storage backends
- [ ] T071 [US8] Add comprehensive migration tests in torii/tests/migration.rs

**Checkpoint**: Database migration tools should be fully functional

---

## Phase 10: Database-Specific Optimizations & Testing

**Purpose**: Implement and test database-specific features for PostgreSQL and MySQL

- [ ] T072 [P] Implement PostgreSQL row-level security policies for tenant isolation in torii-storage-postgres/src/rls.rs
- [ ] T073 [P] Implement MySQL table partitioning strategies for large tenant datasets in torii-storage-seaorm/src/partitioning.rs
- [ ] T074 [P] Add PostgreSQL-specific performance tests with JSONB queries in torii-storage-postgres/tests/performance.rs
- [ ] T075 [P] Add MySQL-specific performance tests with JSON column operations in torii-storage-seaorm/tests/performance.rs
- [ ] T076 [P] Create PostgreSQL connection pooling optimization for tenant-aware connections in torii-storage-postgres/src/pool.rs
- [ ] T077 [P] Create MySQL connection pooling optimization with tenant context in torii-storage-seaorm/src/pool.rs
- [ ] T078 [P] Add database-specific migration rollback procedures in all storage backends
- [ ] T079 [P] Implement PostgreSQL-specific backup/restore procedures for tenant data in torii-storage-postgres/src/backup.rs
- [ ] T080 [P] Implement MySQL-specific backup/restore procedures for tenant data in torii-storage-seaorm/src/backup.rs
- [ ] T081 Add comprehensive database compatibility tests across PostgreSQL versions (12, 13, 14, 15, 16)
- [ ] T082 Add comprehensive database compatibility tests across MySQL versions (8.0, 8.1) and MariaDB (10.6+)

**Checkpoint**: All database-specific optimizations implemented and tested

---

## Phase 11: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [ ] T083 [P] Update library documentation with multi-tenancy examples in docs/
- [ ] T084 [P] Create comprehensive multi-tenant example application in examples/multi-tenant-todos/
- [ ] T085 [P] Add performance benchmarks for multi-tenant vs single-tenant operations in benches/
- [ ] T086 [P] Update README.md with multi-tenancy feature overview
- [ ] T087 [P] Add security audit for tenant isolation in security/
- [ ] T088 Run quickstart.md validation against implemented features
- [ ] T089 Code cleanup and refactoring across all modified crates
- [ ] T079 Performance optimization for tenant-scoped queries

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-10)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3 → P4 → P5 → P6)
- **Polish (Phase 11)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 4 (P4)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 5 (P4)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 6 (P4)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 7 (P5)**: Should start after User Stories 1-6 for comprehensive backward compatibility testing
- **User Story 8 (P6)**: Can start after Foundational (Phase 2) - No dependencies on other stories

### Within Each User Story

- Repository trait extensions before service implementations
- Service implementations before API implementations
- Core implementation before integration tests
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, User Stories 1-6 and 8 can start in parallel (if team capacity allows)
- All repository implementations marked [P] can run in parallel within each story
- Different storage backend implementations can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch all parallel tasks for User Story 1 together:
Task: "Create TenantScoped wrapper struct in torii/src/tenant.rs"
Task: "Implement with_tenant() method on main Torii struct in torii/src/lib.rs"
```

## Parallel Example: User Story 2

```bash
# Launch all storage backend implementations together:
Task: "Implement tenant-scoped UserRepository methods in torii-storage-sqlite/src/repositories/user.rs"
Task: "Implement tenant-scoped UserRepository methods in torii-storage-postgres/src/repositories/user.rs"
Task: "Implement tenant-scoped UserRepository methods in torii-storage-seaorm/src/repositories/user.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Add User Stories 4-6 → Test independently → Deploy/Demo
6. Add User Story 7 → Test backward compatibility → Deploy/Demo
7. Add User Story 8 → Test migration tools → Deploy/Demo
8. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (Tenant-Aware API)
   - Developer B: User Story 2 (Repository Operations)
   - Developer C: User Story 3 (Session APIs)
   - Developer D: User Story 4 (OAuth APIs)
   - Developer E: User Story 5 (Passkey APIs)
   - Developer F: User Story 6 (Magic Link APIs)
3. Stories complete and integrate independently
4. User Story 7 (Backward Compatibility) after stories 1-6
5. User Story 8 (Migration Tools) can be done in parallel with others

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Focus on User Story 1 for MVP - provides core tenant-scoped API functionality
- User Stories 2-3 provide essential repository and session isolation
- User Stories 4-6 extend tenant support to all authentication methods
- User Story 7 ensures existing applications continue to work
- User Story 8 provides migration tools for existing deployments

---

## Summary

**Total Tasks**: 79 tasks
**Task Count per User Story**:
- Setup: 3 tasks
- Foundational: 12 tasks
- User Story 1 (P1): 7 tasks
- User Story 2 (P2): 9 tasks
- User Story 3 (P3): 7 tasks
- User Story 4 (P4): 7 tasks
- User Story 5 (P4): 7 tasks
- User Story 6 (P4): 7 tasks
- User Story 7 (P5): 6 tasks
- User Story 8 (P6): 6 tasks
- Polish: 8 tasks

**Parallel Opportunities**: 45 tasks marked [P] can run in parallel within their phases
**Independent Test Criteria**: Each user story has clear independent test criteria
**Suggested MVP Scope**: User Story 1 (Tenant-Aware API for Library Users)
**Format Validation**: All tasks follow the required checklist format with checkbox, ID, labels, and file paths
