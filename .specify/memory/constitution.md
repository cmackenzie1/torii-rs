<!--
Sync Impact Report:
- Version change: Initial → 1.0.0
- Added principles: Modular Architecture, Type Safety, Security-First, Test-Driven Development, Documentation-First
- Added sections: Security Requirements, Development Workflow
- Templates requiring updates: ✅ All templates reviewed and aligned
- Follow-up TODOs: None
-->

# Torii-rs Constitution

## Core Principles

### I. Modular Architecture
Every feature MUST be implemented as a standalone crate with clear boundaries. Crates MUST be self-contained, independently testable, and documented. Each crate MUST have a single, well-defined purpose - no organizational-only crates allowed.

**Rationale**: Modular design enables independent development, testing, and maintenance while preventing tight coupling that leads to monolithic complexity.

### II. Type Safety
All public APIs MUST use newtype patterns for domain-specific types (e.g., `UserId`, `SessionToken`). Error handling MUST use `thiserror` with structured error types and `#[from]` conversions. Async interfaces MUST use `async_trait`.

**Rationale**: Type safety prevents runtime errors and makes APIs self-documenting, while structured error handling improves debugging and user experience.

### III. Security-First (NON-NEGOTIABLE)
All authentication and authorization code MUST undergo security review before merge. Cryptographic operations MUST use established libraries (no custom crypto). All security-sensitive operations MUST be logged with structured logging.

**Rationale**: Authentication frameworks are high-value targets; security cannot be retrofitted and must be built-in from the start.

### IV. Test-Driven Development
TDD is mandatory for all new features: Tests written → User approved → Tests fail → Then implement. Red-Green-Refactor cycle MUST be strictly enforced. Integration tests MUST cover all authentication flows and storage backend interactions.

**Rationale**: Authentication systems require extremely high reliability; TDD ensures correctness and prevents regressions in security-critical code.

### V. Documentation-First
All public interfaces MUST have comprehensive doc comments before implementation. Each crate MUST include usage examples. Breaking changes MUST be documented with migration guides.

**Rationale**: Authentication frameworks are complex; clear documentation reduces integration errors and improves developer experience.

## Security Requirements

All code MUST follow secure coding practices:
- Input validation on all external data
- Constant-time comparisons for secrets
- Secure random number generation for tokens
- Protection against timing attacks
- Regular dependency security audits

Authentication flows MUST implement:
- Rate limiting on login attempts
- Session timeout and rotation
- Secure token storage recommendations
- Protection against common attacks (CSRF, session fixation, etc.)

## Development Workflow

All changes MUST follow this workflow:
1. Feature specification with security considerations
2. Test implementation (must fail initially)
3. Implementation with security review
4. Documentation updates
5. Integration testing across all storage backends

Code quality gates:
- `make fmt` for formatting
- `make lint` for static analysis
- `make test` for all tests passing
- Security review for auth-related changes

## Governance

This constitution supersedes all other development practices. Amendments require:
1. Documented justification for the change
2. Impact assessment on existing code
3. Migration plan for affected components
4. Approval from project maintainers

All PRs and reviews MUST verify constitutional compliance. Complexity MUST be justified against simpler alternatives. Use `CLAUDE.md` for runtime development guidance and specific tooling instructions.

**Version**: 1.0.0 | **Ratified**: 2025-10-17 | **Last Amended**: 2025-10-17
