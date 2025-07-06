# torii-storage-sqlite

SQLite storage backend for the Torii authentication framework.

This crate provides a complete SQLite-based storage implementation for Torii, including all core authentication features like user management, sessions, passwords, OAuth, passkeys, and magic links.

## Features

- **User Management**: Store and retrieve user accounts with email verification support
- **Session Management**: Handle user sessions with configurable expiration
- **Password Authentication**: Secure password hashing and verification
- **OAuth Integration**: Store OAuth account connections and tokens
- **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
- **Magic Link Authentication**: Generate and verify magic links for passwordless login
- **Database Migrations**: Automatic schema management and upgrades

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
torii-storage-sqlite = "0.2"
```

### Basic Setup

```rust
use torii_storage_sqlite::SqliteStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to SQLite database
    let storage = SqliteStorage::connect("sqlite://todos.db?mode=rwc").await?;
    
    // Run migrations to set up the schema
    storage.migrate().await?;
    
    // Use with Torii
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = torii::Torii::new(repositories);
    
    Ok(())
}
```

### With Password Authentication

```rust
use torii_storage_sqlite::SqliteStorage;
use torii::{Torii, SessionConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?;
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

## Database Schema

The SQLite schema includes the following tables:

- `users` - User accounts and profile information
- `sessions` - Active user sessions
- `passwords` - Hashed password credentials
- `oauth_accounts` - Connected OAuth accounts
- `passkeys` - WebAuthn passkey credentials
- `passkey_challenges` - Temporary passkey challenges
- `magic_links` - Magic link tokens and metadata

All tables include appropriate indexes for optimal query performance.

## Repository Provider

This crate provides `SqliteRepositoryProvider` which implements the `RepositoryProvider` trait from `torii-core`, allowing it to be used directly with the main Torii authentication coordinator.

## Storage Implementations

This crate implements the following storage traits:

- `UserStorage` - User account management
- `SessionStorage` - Session management
- Password repository for secure password storage
- OAuth repository for third-party authentication
- Passkey repository for WebAuthn support
- Magic link repository for passwordless authentication
