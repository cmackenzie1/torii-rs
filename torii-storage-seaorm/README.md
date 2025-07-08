# torii-storage-seaorm

SeaORM storage backend for the Torii authentication framework.

This crate provides a SeaORM-based storage implementation for Torii that works with multiple database backends including PostgreSQL, MySQL, and SQLite. SeaORM is a modern async ORM for Rust that provides type-safe database operations and excellent performance.

## Features

- **Multi-Database Support**: Works with PostgreSQL, MySQL, and SQLite through SeaORM
- **Type-Safe Operations**: Leverages SeaORM's compile-time query validation
- **Async/Await**: Fully async database operations with tokio
- **Automatic Migrations**: Built-in schema migration management
- **User Management**: Store and retrieve user accounts with email verification support
- **Session Management**: Handle user sessions with configurable expiration
- **Password Authentication**: Secure password hashing and verification
- **OAuth Integration**: Store OAuth account connections and tokens
- **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
- **Magic Link Authentication**: Generate and verify magic links for passwordless login

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
torii-storage-seaorm = "0.4.0"
```

### Basic Setup

```rust
use torii_storage_seaorm::SeaORMStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to database (supports PostgreSQL, MySQL, SQLite)
    let storage = SeaORMStorage::connect("sqlite://todos.db?mode=rwc").await?;
    
    // Run migrations to set up the schema
    storage.migrate().await?;
    
    // Convert to repository provider and use with Torii
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = torii::Torii::new(repositories);
    
    Ok(())
}
```

### With Different Databases

```rust
use torii_storage_seaorm::SeaORMStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // PostgreSQL
    let storage = SeaORMStorage::connect("postgresql://user:password@localhost/torii").await?;
    
    // MySQL
    // let storage = SeaORMStorage::connect("mysql://user:password@localhost/torii").await?;
    
    // SQLite
    // let storage = SeaORMStorage::connect("sqlite://auth.db?mode=rwc").await?;
    
    storage.migrate().await?;
    
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = torii::Torii::new(repositories);
    
    Ok(())
}
```

### With Password Authentication

```rust
use torii_storage_seaorm::SeaORMStorage;
use torii::Torii;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = SeaORMStorage::connect("sqlite://auth.db?mode=rwc").await?;
    storage.migrate().await?;
    
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Torii::new(repositories);
    
    // Register a user
    let user = torii.register_user_with_password("user@example.com", "secure_password").await?;
    
    // Login
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

## Database Support

This crate can be used with any database backend supported by SeaORM:

- **PostgreSQL**: Production-ready with full feature support
- **MySQL**: Production-ready with full feature support  
- **SQLite**: Great for development and smaller deployments

## Repository Provider

This crate provides `SeaORMRepositoryProvider` which implements the `RepositoryProvider` trait from `torii-core`, allowing it to be used directly with the main Torii authentication coordinator.

## Entity Models

The crate defines SeaORM entity models for all authentication data:

- `User` - User accounts and profile information
- `Session` - Active user sessions
- `Password` - Hashed password credentials  
- `OAuthAccount` - Connected OAuth accounts
- `Passkey` - WebAuthn passkey credentials
- `PasskeyChallenge` - Temporary passkey challenges
- `MagicLink` - Magic link tokens and metadata

All entities include appropriate relationships and indexes for optimal performance.

## Storage Implementations

This crate implements repository patterns for:

- User account management and profile storage
- Session management with automatic expiration
- Password credential storage with secure hashing
- OAuth account connections and token management
- WebAuthn passkey credentials and challenge handling
- Magic link token generation and verification

## Migration Management

The crate includes built-in migration management through SeaORM's migration system. All necessary tables and indexes are automatically created when you call `migrate()`.

## Performance

SeaORM provides excellent performance characteristics:
- Compile-time query validation prevents runtime errors
- Efficient connection pooling
- Prepared statement caching
- Automatic query optimization