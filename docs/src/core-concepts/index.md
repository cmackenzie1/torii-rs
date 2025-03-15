# Core Concepts

Torii is built around several core concepts that form the foundation of the authentication system. Understanding these concepts is essential for effectively implementing and extending Torii in your applications.

## Main Components

The Torii framework consists of several key components:

1. **The Torii Coordinator**: The main `Torii` struct that coordinates all authentication activities
2. **Storage Backends**: Implementations for persisting user and session data
3. **Authentication Plugins**: Modules for different authentication methods
4. **User and Session Management**: APIs for creating and verifying sessions

## Users

Users are the central entity in the Torii authentication system. Each user represents an individual who can authenticate with your application.

### User Structure

The core `User` struct contains the following fields:

| Field             | Type                    | Description                                    |
| ----------------- | ----------------------- | ---------------------------------------------- |
| id                | `UserId`                | The unique identifier for the user             |
| name              | `Option<String>`        | The user's name (optional)                     |
| email             | `String`                | The user's email address                       |
| email_verified_at | `Option<DateTime<Utc>>` | Timestamp when the email was verified (if any) |
| created_at        | `DateTime<Utc>`         | Timestamp when the user was created            |
| updated_at        | `DateTime<Utc>`         | Timestamp when the user was last updated       |

### User IDs

Each user has a unique `UserId` that identifies them in the system. This ID is:

- Stable and will not change during the user's lifetime
- Treated as an opaque identifier rather than a specific format (though it uses UUIDs internally by default)
- Used to link user accounts to authentication methods, sessions, and application data

## Sessions

Sessions represent authenticated user sessions and are created when a user successfully logs in.

### Session Structure

The `Session` struct contains the following fields:

| Field      | Type             | Description                                           |
| ---------- | ---------------- | ----------------------------------------------------- |
| token      | `SessionToken`   | The unique token identifying the session              |
| user_id    | `UserId`         | The ID of the authenticated user                      |
| user_agent | `Option<String>` | The user agent of the client that created the session |
| ip_address | `Option<String>` | The IP address of the client that created the session |
| created_at | `DateTime<Utc>`  | Timestamp when the session was created                |
| expires_at | `DateTime<Utc>`  | Timestamp when the session will expire                |

### Session Tokens

Each session is identified by a unique `SessionToken` that:

- Functions as a bearer token or cookie for authentication
- Should be kept secret and transmitted securely (e.g., via HTTPS)
- Has an expiration time after which it will no longer be valid
- Can be revoked to force a user to log out

### Session Types

Torii supports two types of sessions:

1. **Database Sessions** (default): Sessions are stored in your database and can be individually revoked
2. **JWT Sessions** (optional): Stateless sessions using JWT tokens that don't require database lookups but cannot be individually revoked

## Authentication Methods

Torii provides several authentication methods through its plugin system:

### Password Authentication

Traditional email/password authentication with secure password hashing.

Key features:
- Argon2id password hashing
- Email verification capabilities
- Password reset functionality

### OAuth Authentication

Social login and OpenID Connect support for external identity providers.

Supported providers:
- Google
- GitHub
- More providers can be added

### Passkey Authentication (WebAuthn)

Passwordless authentication using the Web Authentication API (WebAuthn).

Key features:
- FIDO2-compliant
- Supports hardware security keys, platform authenticators (Windows Hello, Touch ID, etc.)
- Challenge-response authentication flow

### Magic Link Authentication

Email-based passwordless authentication using one-time tokens.

Key features:
- Generates secure tokens
- Time-limited validation
- Simple user experience

## Storage System

Torii abstracts the storage layer through traits, allowing different storage backend implementations:

### Available Storage Backends

1. **SQLite**: For development, testing, or small applications
2. **PostgreSQL**: For production-ready applications requiring a robust database
3. **SeaORM**: Supporting SQLite, PostgreSQL, and MySQL through the SeaORM ORM

Each storage backend implements the following core storage traits:
- `UserStorage`: For user management
- `SessionStorage`: For session management
- `PasswordStorage`: For password authentication
- `OAuthStorage`: For OAuth accounts
- `PasskeyStorage`: For WebAuthn credentials
- `MagicLinkStorage`: For magic link tokens

## Initialization Patterns

Torii provides several ways to initialize the system based on your application's needs:

1. **Single Storage**: Use the same storage for users and sessions
   ```rust
   Torii::new(storage)
   ```

2. **Split Storage**: Use different storage backends for users and sessions
   ```rust
   Torii::with_storages(user_storage, session_storage)
   ```

3. **Custom Managers**: Provide custom user and session managers
   ```rust
   Torii::with_managers(user_storage, session_storage, user_manager, session_manager)
   ```

4. **Stateless Managers**: Use custom managers without storage
   ```rust
   Torii::with_custom_managers(user_manager, session_manager)
   ```

## Error Handling

Torii uses a structured error system with the `ToriiError` enum that includes:

- `PluginNotFound`: When an authentication plugin is not available
- `AuthError`: When authentication fails
- `StorageError`: When there's an issue with the storage backend

Understanding these core concepts provides the foundation for working with Torii's authentication flows in your applications.
