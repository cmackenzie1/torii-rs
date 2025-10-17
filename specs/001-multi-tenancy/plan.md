# Implementation Plan: Multi-Tenancy Support

**Branch**: `001-multi-tenancy` | **Date**: 2025-10-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-multi-tenancy/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Add multi-tenancy support to the torii-rs authentication library by providing tenant-scoped APIs that automatically isolate user data by tenant. The library will extend existing entities with tenant_id fields, provide `with_tenant(id)` APIs for all authentication operations, and maintain backward compatibility with existing single-tenant usage through a default tenant mechanism.

## Technical Context

**Language/Version**: Rust 1.75+ (current MSRV, using async/await, tokio runtime)
**Primary Dependencies**: tokio, sea-orm, sqlx, async-trait, thiserror, chrono, serde
**Storage**: SQLite, PostgreSQL (with RLS and JSONB optimizations), MySQL (with JSON columns and partitioning via SeaORM)
**Testing**: cargo test with tokio::test for async tests, cargo nextest for test execution
**Target Platform**: Cross-platform library (Linux, macOS, Windows) for server applications
**Project Type**: Multi-crate Rust library workspace with storage backend abstractions
**Performance Goals**: <10% overhead for multi-tenant operations vs single-tenant, <50ms session validation
**Constraints**: Backward compatibility required (no breaking API changes), database schema migrations must be non-destructive
**Scale/Scope**: Support 1000+ tenants per deployment, extend 8 existing crates, add tenant context to 15+ entity types

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Based on project guidelines from CONTRIBUTING.md, CLAUDE.md, and project structure:

✅ **Service-Oriented Architecture**: Multi-tenancy will extend existing service architecture without breaking it
✅ **Type Safety**: Will use newtype patterns (TenantId) and extend existing strongly-typed entities
✅ **Async/Await**: All new APIs will be async-compatible with tokio runtime
✅ **Error Handling**: Will use thiserror for structured error types with tenant-specific errors
✅ **Testing**: Will include unit tests with #[tokio::test] and integration tests for all storage backends
✅ **Documentation**: Will add doc comments to all new public APIs and tenant-scoped interfaces
✅ **Backward Compatibility**: Explicitly required - existing single-tenant APIs must work unchanged
✅ **Code Style**: Will follow existing patterns (PascalCase types, snake_case functions, builder patterns)
✅ **Multi-Backend Support**: Will extend all storage backends (SQLite, PostgreSQL, MySQL) consistently

## Project Structure

### Documentation (this feature)

```
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```
torii-rs/ (workspace root)
├── torii-core/                    # Core types, traits, services (MODIFY)
│   ├── src/
│   │   ├── repositories/          # Add tenant-aware repository traits
│   │   ├── services/              # Extend services with tenant context
│   │   ├── session/               # Add tenant context to sessions
│   │   ├── user.rs                # Add tenant_id field
│   │   └── tenant.rs              # NEW: TenantId, TenantContext types
│   └── tests/
├── torii-storage-sqlite/          # SQLite backend (MODIFY)
│   ├── src/
│   │   ├── migrations/            # Add tenant column migrations
│   │   ├── repositories/          # Add tenant filtering to queries
│   │   └── lib.rs                 # Extend with tenant support
│   └── tests/
├── torii-storage-postgres/        # PostgreSQL backend (MODIFY)
│   ├── src/
│   │   ├── migrations/            # Add tenant column migrations with RLS
│   │   ├── repositories/          # Add tenant filtering with JSONB support
│   │   ├── rls.rs                 # Row-level security policies
│   │   ├── pool.rs                # Tenant-aware connection pooling
│   │   └── lib.rs                 # Extend with PostgreSQL-specific features
│   └── tests/
├── torii-storage-seaorm/          # SeaORM backend for MySQL/multi-DB (MODIFY)
│   ├── src/
│   │   ├── entities/              # Add tenant_id to all entity models
│   │   ├── migrations/            # Add tenant column migrations for MySQL
│   │   ├── repositories/          # Add tenant filtering with JSON columns
│   │   ├── partitioning.rs        # MySQL table partitioning strategies
│   │   ├── pool.rs                # MySQL tenant-aware connection pooling
│   │   └── lib.rs                 # Extend with MySQL-specific optimizations
│   └── tests/
├── torii/                         # Main library (MODIFY)
│   ├── src/
│   │   └── lib.rs                 # Add with_tenant() API
│   └── tests/
└── examples/                      # Add multi-tenant examples
    └── multi-tenant-todos/        # NEW: Multi-tenant version of todos
```

**Structure Decision**: Multi-crate workspace modification - extending existing crates rather than creating new ones. This maintains the established architecture while adding tenant capabilities throughout the stack.

## Complexity Tracking

*Fill ONLY if Constitution Check has violations that must be justified*

No violations identified. The multi-tenancy implementation follows all established project guidelines:
- Extends existing service architecture without breaking it
- Uses established patterns (newtype, async/await, thiserror)
- Maintains backward compatibility as required
- Follows existing code style and testing practices

## Post-Design Constitution Re-Check

✅ **Service-Oriented Architecture**: Design extends existing services with tenant context
✅ **Type Safety**: TenantId newtype and tenant-scoped APIs provide compile-time safety
✅ **Async/Await**: All new APIs are async-compatible with existing tokio patterns
✅ **Error Handling**: TenantError extends existing thiserror-based error handling
✅ **Testing**: Design includes unit and integration tests for all storage backends
✅ **Documentation**: Comprehensive API documentation and quickstart guide provided
✅ **Backward Compatibility**: Existing APIs work unchanged via default tenant mechanism
✅ **Code Style**: Follows established patterns throughout the codebase
✅ **Multi-Backend Support**: Consistent extension across SQLite, PostgreSQL, MySQL backends

All constitution requirements satisfied. Ready for implementation.

