# Torii

[![CI](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/cmackenzie1/torii-rs/branch/main/graph/badge.svg?token=MHF0G453L0)](https://codecov.io/gh/cmackenzie1/torii-rs)
[![docs.rs](https://img.shields.io/docsrs/torii)](https://docs.rs/torii/latest/torii/)
[![Crates.io Version](https://img.shields.io/crates/v/torii)](https://crates.io/crates/torii)

> [!WARNING]
> This project is in early development and is not production-ready. The API is subject to change without notice.

## Overview

Torii is a powerful authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features through a flexible service architecture.

With Torii, you get the best of both worlds - powerful authentication capabilities like passwordless login, social OAuth, and passkeys, combined with full data sovereignty and the ability to store user data wherever you choose.

Check out the example [todos](./examples/todos/README.md) to see Torii in action.

## Features

- **Password Authentication**: Secure password-based login with bcrypt hashing
- **OAuth/OpenID Connect**: Social login with major providers (Google, GitHub, etc.) 
- **Passkey/WebAuthn**: Modern passwordless authentication with FIDO2
- **Magic Links**: Email-based passwordless authentication
- **Session Management**: Flexible session handling (opaque tokens or JWTs)
- **Full Data Sovereignty**: Store user data where you choose
- **Multiple Storage Backends**: SQLite, PostgreSQL, MySQL support
- **Type Safety**: Strongly typed APIs with compile-time guarantees
- **Async/Await**: Built for modern async Rust applications

## Storage Backend Support

| Authentication Method | SQLite | PostgreSQL | MySQL (SeaORM) |
|-----------------------|--------|------------|----------------|
| Password              | ✅     | ✅         | ✅             |
| OAuth2/OIDC           | ✅     | ✅         | ✅             |
| Passkey/WebAuthn      | ✅     | ✅         | ✅             |
| Magic Link            | ✅     | ✅         | ✅             |

✅ = Supported
🚧 = Planned/In Development
❌ = Not Supported

## Quick Start

Add Torii to your `Cargo.toml`:

```toml
[dependencies]
torii = { version = "0.4.0", features = ["sqlite", "password"] }
```

Basic usage example:

```rust
use torii::Torii;
use torii::sqlite::SqliteStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to database
    let storage = SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?;
    storage.migrate().await?;
    
    // Create Torii instance
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Torii::new(repositories);
    
    // Register a user
    let user = torii.password().register(
        "user@example.com", 
        "secure_password"
    ).await?;
    
    // Login user
    let (user, session) = torii.password().authenticate(
        "user@example.com", 
        "secure_password",
        None, // user_agent
        None, // ip_address
    ).await?;
    
    println!("User logged in: {}", user.email);
    Ok(())
}
```

### Axum Integration

For web applications, use the `torii-axum` crate for plug-and-play integration:

```toml
[dependencies]
torii-axum = { version = "0.4.0", features = ["sqlite", "password"] }
```

```rust
use torii_axum::{AuthRoutes, CookieConfig, AuthUser};
use axum::{routing::get, Router, Json};

#[tokio::main]
async fn main() {
    let storage = /* ... setup storage ... */;
    let torii = /* ... setup torii ... */;
    
    // Create authentication routes with cookie configuration
    let auth_routes = AuthRoutes::new(torii.clone())
        .with_cookie_config(CookieConfig::development());
    
    // Build your application with auth routes
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .merge(auth_routes.into_router())
        .with_state(torii);
    
    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Protected route handler
async fn protected_handler(user: AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.id,
        "email": user.email
    }))
}
```

## Project Structure

The Torii project is organized into several crates:

### Core Crates

- **[`torii`](./torii/)** - Main authentication coordinator and public API
- **[`torii-core`](./torii-core/)** - Core types, traits, and services
- **[`torii-migration`](./torii-migration/)** - Database migration management

### Storage Backends

- **[`torii-storage-sqlite`](./torii-storage-sqlite/)** - SQLite storage implementation
- **[`torii-storage-postgres`](./torii-storage-postgres/)** - PostgreSQL storage implementation  
- **[`torii-storage-seaorm`](./torii-storage-seaorm/)** - Multi-database storage via SeaORM (SQLite, PostgreSQL, MySQL)

### Integration Crates

- **[`torii-axum`](./torii-axum/)** - Plug-and-play Axum integration with routes, middleware, and extractors

### Examples

- **[`examples/todos`](./examples/todos/)** - Complete todo application demonstrating Torii integration
- **[`examples/axum-example`](./examples/axum-example/)** - Complete Axum web server with SQLite, password authentication, and email support

## Architecture

Torii uses a service-oriented architecture:

- **Services**: Handle business logic for authentication methods (password, OAuth, etc.)
- **Repositories**: Provide data access abstractions for different storage backends
- **Storage Backends**: Implement concrete database operations
- **Session Providers**: Handle session token generation and validation (opaque or JWT)

This modular design allows you to mix and match components based on your needs while maintaining type safety and performance.

## Security

> [!IMPORTANT]
> As this project is in early development, it has not undergone security audits and should not be used in production environments. The maintainers are not responsible for any security issues that may arise from using this software.

## Contributing

As this project is in its early stages, we welcome discussions and feedback, but please note that major changes may occur.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
