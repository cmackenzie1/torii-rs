# torii-core

Core functionality for the Torii authentication framework.

This crate provides the foundational types, traits, and services that power the Torii authentication system. It defines the core abstractions for users, sessions, and authentication methods while providing a flexible service architecture that can be extended with different storage backends.

## Features

- **User Management**: Core user types and management services
- **Session Management**: Flexible session handling with both opaque and JWT tokens
- **Service Architecture**: Modular services for different authentication methods
- **Storage Abstraction**: Database-agnostic storage traits and repository patterns
- **Type Safety**: Strongly typed IDs and newtype patterns for security
- **Async/Await**: Fully async operations with tokio support
- **Error Handling**: Comprehensive error types with structured error handling

## Core Types

### Users

Users are the foundation of the authentication system. The `User` struct includes:

| Field               | Type               | Description                                       |
| ------------------- | ------------------ | ------------------------------------------------- |
| `id`                | `UserId`           | The unique identifier for the user                |
| `name`              | `Option<String>`   | The display name of the user                      |
| `email`             | `String`           | The email address of the user                     |
| `email_verified_at` | `Option<DateTime>` | The timestamp when the user's email was verified |
| `created_at`        | `DateTime`         | The timestamp when the user was created          |
| `updated_at`        | `DateTime`         | The timestamp when the user was last updated     |

### Sessions

Sessions track user authentication state and can be implemented as either opaque tokens or JWTs:

| Field        | Type             | Description                                            |
| ------------ | ---------------- | ------------------------------------------------------ |
| `token`      | `SessionToken`   | The session token (opaque or JWT)                     |
| `user_id`    | `UserId`         | The unique identifier for the user                     |
| `user_agent` | `Option<String>` | The user agent of the client that created the session |
| `ip_address` | `Option<String>` | The IP address of the client that created the session |
| `created_at` | `DateTime`       | The timestamp when the session was created            |
| `updated_at` | `DateTime`       | The timestamp when the session was last updated       |
| `expires_at` | `DateTime`       | The timestamp when the session expires                |

## Service Architecture

Torii uses a service-oriented architecture with the following core services:

### UserService

Handles user account management:
- User creation and updates
- Email verification
- User deletion
- User retrieval by ID or email

### SessionService

Manages user sessions:
- Session creation with configurable expiration
- Session validation and retrieval
- Session deletion and cleanup
- Multi-device session management

### Authentication Services

Specialized services for different authentication methods:
- `PasswordService` - Password-based authentication
- `OAuthService` - OAuth/OpenID Connect integration
- `PasskeyService` - WebAuthn/FIDO2 passkey authentication
- `MagicLinkService` - Passwordless magic link authentication

## Storage Abstraction

The crate defines storage traits that can be implemented by different backends:

### UserStorage

```rust
#[async_trait]
pub trait UserStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error>;
    async fn update_user(&self, user: &User) -> Result<User, Self::Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error>;
    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Self::Error>;
}
```

### SessionStorage

```rust
#[async_trait]
pub trait SessionStorage: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    async fn create_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Self::Error>;
    async fn update_session(&self, session: &Session) -> Result<Session, Self::Error>;
    async fn delete_session(&self, token: &SessionToken) -> Result<(), Self::Error>;
    async fn delete_user_sessions(&self, user_id: &UserId) -> Result<(), Self::Error>;
}
```

## Repository Provider

The `RepositoryProvider` trait allows storage backends to provide all necessary repositories:

```rust
#[async_trait]
pub trait RepositoryProvider: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn user_repository(&self) -> &dyn UserRepository<Error = Self::Error>;
    fn session_repository(&self) -> &dyn SessionRepository<Error = Self::Error>;
    fn password_repository(&self) -> &dyn PasswordRepository<Error = Self::Error>;
    // ... other repositories

    async fn migrate(&self) -> Result<(), Self::Error>;
    async fn health_check(&self) -> Result<(), Self::Error>;
}
```

## Session Providers

Torii supports two session token types:

### Opaque Sessions

Traditional session tokens stored in the database:
- Random token generation
- Server-side session validation
- Immediate revocation capability
- Requires database lookup for validation

### JWT Sessions

Self-contained JSON Web Tokens:
- Stateless authentication
- Configurable signing algorithms (HS256, HS384, HS512, RS256, etc.)
- Custom claims support
- No database lookup required for validation

## Type Safety

The crate uses newtype patterns for enhanced type safety:

```rust
// Strongly typed IDs prevent mixing different ID types
pub struct UserId(String);
pub struct SessionToken(String);

// Builder patterns for safe construction
let user = User::builder()
    .id(UserId::new("user_123"))
    .email("user@example.com")
    .build()?;
```

## Error Handling

Comprehensive error handling with structured error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("Authentication error: {0}")]
    Authentication(String),
    #[error("Validation error: {0}")]
    Validation(String),
}
```

## Usage

This crate is typically used indirectly through the main `torii` crate, but can be used directly for custom implementations:

```rust
use torii_core::{
    UserService, SessionService, User, UserId,
    repositories::UserRepositoryAdapter,
    storage::UserStorage,
};

// Create services with your storage backend
let user_service = UserService::new(user_repository);
let session_service = SessionService::new(session_provider);

// Use the services
let user = user_service.create_user(&new_user).await?;
let session = session_service.create_session(&user.id, None, None, duration).await?;
```

## Integration

Storage backends like `torii-storage-sqlite`, `torii-storage-postgres`, and `torii-storage-seaorm` implement the traits defined in this crate to provide concrete storage implementations.
