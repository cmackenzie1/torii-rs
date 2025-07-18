# Getting Started with Torii

This guide will get you up and running with Torii authentication in your Rust application.

## Prerequisites

- A Rust project with Cargo
- Basic understanding of async Rust
- Database (SQLite, PostgreSQL, or MySQL)

## Installation

Add Torii to your `Cargo.toml`:

```toml
[dependencies]
torii = { version = "0.4.0", features = ["password", "sqlite"] }
tokio = { version = "1", features = ["full"] }
```

### Available Features

**Authentication Methods:**
- `password` - Email/password authentication
- `oauth` - OAuth/social login
- `passkey` - WebAuthn/passkey authentication
- `magic-link` - Email magic link authentication

**Storage Backends:**
- `sqlite` - SQLite storage
- `postgres` - PostgreSQL storage
- `seaorm` - SeaORM support (SQLite, PostgreSQL, MySQL)

## Basic Setup

Here's a complete example with SQLite and password authentication:

```rust,edition2024
{{#include code/getting-started/basic-setup.rs}}
```

## User Registration and Login

### Register a User

```rust,edition2024,ignore,ignore
{{#include code/getting-started/register-user.rs}}
```

### Login a User

```rust,edition2024,ignore,ignore
{{#include code/getting-started/login-user.rs}}
```

### Verify a Session

```rust,edition2024,ignore,ignore
{{#include code/getting-started/verify-session.rs}}
```

## Session Types

### Database Sessions (Default)
Sessions are stored in your database and can be revoked immediately:

```rust,edition2024,ignore,ignore
{{#include code/getting-started/opaque-sessions.rs}}
```

### JWT Sessions
Self-contained tokens that don't require database lookups:

```rust,edition2024,ignore,ignore
{{#include code/getting-started/jwt-sessions.rs}}
```

## Web Framework Integration

### Axum Integration

For quick web integration, use the `torii-axum` crate:

```toml
[dependencies]
torii-axum = { version = "0.4.0", features = ["password", "sqlite"] }
```

```rust,edition2024,ignore,ignore
{{#include code/getting-started/axum-integration.rs}}
```

This provides automatic endpoints:
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `GET /auth/user` - Get current user
- `POST /auth/logout` - User logout

## Other Authentication Methods

Torii provides organized namespaces for different authentication methods:

- **`torii.password()`**: Traditional email/password authentication
- **`torii.oauth()`**: Social login (Google, GitHub, etc.)  
- **`torii.passkey()`**: Modern biometric authentication
- **`torii.magic_link()`**: Email-based passwordless login

Each namespace contains focused methods for that authentication type.

### OAuth Authentication

```rust,edition2024,ignore,ignore
{{#include code/getting-started/oauth-start.rs}}
```

### Magic Link Authentication

```rust,edition2024,ignore,ignore
// Generate magic token
let token = torii.magic_link().generate_token("user@example.com").await?;

// Verify magic token
let (user, session) = torii.magic_link().authenticate(
    &token.token,
    Some("Browser".to_string()),
    Some("127.0.0.1".to_string())
).await?;
```

## Examples

Check out the complete examples in the repository:

- **[examples/axum-example](https://github.com/cmackenzie1/torii-rs/tree/main/examples/axum-example)** - Complete web server with authentication and email support
- **[examples/todos](https://github.com/cmackenzie1/torii-rs/tree/main/examples/todos)** - Complete todo application

## Next Steps

- Learn about [Core Concepts](./core-concepts/index.md) for deeper understanding
- Explore different authentication methods
- Configure production storage backends
- Add email verification and password reset functionality

Remember: Torii gives you complete control over your user data while providing modern authentication features.
