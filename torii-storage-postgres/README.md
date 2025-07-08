# torii-storage-postgres

PostgreSQL storage backend for the Torii authentication framework.

This crate provides a complete PostgreSQL-based storage implementation for Torii, including all core authentication features like user management, sessions, passwords, OAuth, passkeys, and magic links. It is designed for production workloads that require high performance and reliability.

## Features

- **User Management**: Store and retrieve user accounts with email verification support
- **Session Management**: Handle user sessions with configurable expiration
- **Password Authentication**: Secure password hashing and verification
- **OAuth Integration**: Store OAuth account connections and tokens
- **Passkey Support**: WebAuthn/FIDO2 passkey storage and challenge management
- **Magic Link Authentication**: Generate and verify magic links for passwordless login
- **Database Migrations**: Automatic schema management and upgrades
- **Production Ready**: Optimized for high-performance production workloads

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
torii-storage-postgres = "0.4.0"
```

### Basic Setup

```rust
use torii_storage_postgres::PostgresStorage;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to PostgreSQL database
    let storage = PostgresStorage::connect("postgresql://user:password@localhost/torii").await?;
    
    // Run migrations to set up the schema
    storage.migrate().await?;
    
    // Note: PostgresRepositoryProvider is still in development
    // let repositories = Arc::new(storage.into_repository_provider());
    // let torii = torii::Torii::new(repositories);
    
    Ok(())
}
```

### With Connection Pool

```rust
use torii_storage_postgres::PostgresStorage;
use sqlx::PgPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a connection pool
    let pool = PgPool::connect("postgresql://user:password@localhost/torii").await?;
    
    // Create storage instance
    let storage = PostgresStorage::new(pool);
    
    // Run migrations
    storage.migrate().await?;
    
    Ok(())
}
```

## Database Schema

The PostgreSQL schema includes the following tables:

- `users` - User accounts and profile information
- `sessions` - Active user sessions
- `passwords` - Hashed password credentials
- `oauth_accounts` - Connected OAuth accounts
- `passkeys` - WebAuthn passkey credentials
- `passkey_challenges` - Temporary passkey challenges
- `magic_links` - Magic link tokens and metadata

All tables include appropriate indexes and constraints for optimal query performance and data integrity.

## Current Status

This crate currently provides the base PostgreSQL storage implementation with user and session management. The full repository provider implementation is still in development and will be available in future releases.

## Storage Implementations

This crate implements the following storage traits:

- `UserStorage` - User account management
- `SessionStorage` - Session management
- Password repository for secure password storage
- OAuth repository for third-party authentication
- Passkey repository for WebAuthn support
- Magic link repository for passwordless authentication

## Connection Requirements

- PostgreSQL 12+ recommended
- Requires `uuid-ossp` extension for UUID generation
- Proper user permissions for table creation and data manipulation
