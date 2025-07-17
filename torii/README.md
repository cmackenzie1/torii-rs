# Torii

[![CI](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/cmackenzie1/torii-rs/branch/main/graph/badge.svg?token=MHF0G453L0)](https://codecov.io/gh/cmackenzie1/torii-rs)
[![docs.rs](https://img.shields.io/docsrs/torii)](https://docs.rs/torii/latest/torii/)
[![Crates.io Version](https://img.shields.io/crates/v/torii)](https://crates.io/crates/torii)

Torii is a powerful authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features through a flexible plugin system.

## Features

- **Password Authentication**: Secure password-based login with bcrypt hashing
- **OAuth/OpenID Connect**: Social login with major providers (Google, GitHub, etc.)
- **Passkey/WebAuthn**: Modern passwordless authentication with FIDO2
- **Magic Links**: Email-based passwordless authentication
- **Session Management**: Flexible session handling (opaque tokens or JWTs)
- **Full Data Sovereignty**: Store user data where you choose
- **Multiple Storage Backends**: SQLite, PostgreSQL, MySQL support via SeaORM
- **Type Safety**: Strongly typed APIs with compile-time guarantees
- **Async/Await**: Built for modern async Rust applications

## Quick Start

1. Add dependencies to your `Cargo.toml`:

```toml
[dependencies]
torii = { version = "0.2.0", features = ["sqlite", "password"] }
```

2. Set up your application:

```rust
use torii::{Torii, SessionConfig};
use torii::sqlite::SqliteStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to database
    let storage = SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?;
    
    // Run migrations
    storage.migrate().await?;
    
    // Create Torii instance
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Torii::new(repositories);
    
    // Register a user
    let user = torii.register_user_with_password("user@example.com", "secure_password").await?;
    println!("Created user: {}", user.email);
    
    // Login user
    let (user, session) = torii.login_user_with_password(
        "user@example.com", 
        "secure_password",
        None, // user_agent
        None, // ip_address
    ).await?;
    
    println!("User logged in: {}", user.email);
    println!("Session token: {}", session.token);
    
    Ok(())
}
```

## Storage Backends

Choose the storage backend that fits your needs:

### SQLite (Development & Small Apps)

```toml
[dependencies]
torii = { version = "0.2.0", features = ["sqlite", "password"] }
```

### PostgreSQL (Production)

```toml
[dependencies]
torii = { version = "0.2.0", features = ["seaorm-postgres", "password"] }
```

### MySQL (Production)

```toml
[dependencies]
torii = { version = "0.2.0", features = ["seaorm-mysql", "password"] }
```

## Authentication Methods

### Password Authentication

```rust
// Enable password auth
let torii = Torii::new(repositories);

// Register user
let user = torii.register_user_with_password("user@example.com", "password").await?;

// Login
let (user, session) = torii.login_user_with_password(
    "user@example.com", 
    "password",
    Some("Mozilla/5.0...".to_string()), // user_agent
    Some("192.168.1.1".to_string()),    // ip_address
).await?;
```

### JWT Sessions

```rust
use torii::{Torii, SessionConfig, JwtConfig, JwtAlgorithm};

let jwt_config = JwtConfig::new("your-secret-key", JwtAlgorithm::HS256);
let session_config = SessionConfig::default().with_jwt(jwt_config);

let torii = Torii::new(repositories).with_session_config(session_config);
```
