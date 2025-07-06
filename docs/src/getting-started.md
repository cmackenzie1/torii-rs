# Getting Started with Torii

This guide will walk you through the process of integrating Torii into your Rust application. By the end, you'll have a fully functional authentication system supporting multiple authentication methods.

## Prerequisites

Before you begin, make sure you have:

- A Rust project set up with Cargo
- Basic understanding of async Rust (Torii uses `async`/`await`)
- Database setup for your preferred storage backend (SQLite, PostgreSQL, or MySQL)

## Installation

Add Torii to your `Cargo.toml` file:

```toml
[dependencies]
torii = { version = "0.3", features = ["password", "sqlite"] }
tokio = { version = "1", features = ["full"] }
```

The features you choose will depend on your authentication needs:

- Authentication methods:
  - `password`: Email/password authentication
  - `oauth`: OAuth/social login support
  - `passkey`: WebAuthn/passkey authentication
  - `magic-link`: Email magic link authentication
- Storage backends:
  - `sqlite`: SQLite storage
  - `postgres`: PostgreSQL storage
  - `seaorm`: SeaORM support with additional options (`seaorm-sqlite`, `seaorm-postgres`, or `seaorm-mysql`)

## Basic Setup

Here's a minimal example to set up Torii with a SQLite database and password authentication:

```rust,no_run
use std::sync::Arc;
use torii::Torii;
use torii::SqliteRepositoryProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the database connection
    let pool = sqlx::SqlitePool::connect("sqlite://auth.db?mode=rwc").await?;
    
    // Create repository provider
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
    
    // Migrate the database schema
    repositories.migrate().await?;

    // Create a Torii instance
    let torii = Torii::new(repositories);

    // Now torii is ready to use for authentication
    Ok(())
}
```

## Session Configuration

Torii supports two types of session management:

### Opaque Sessions (Default)

Database-backed sessions with immediate revocation support:

```rust,no_run
use std::sync::Arc;
use torii::{Torii, SessionConfig};
use chrono::Duration;

let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .expires_in(Duration::days(30))
    );
```

### JWT Sessions

Stateless sessions with better performance for distributed systems:

```rust,no_run
use torii::{Torii, JwtConfig, SessionConfig};
use chrono::Duration;

// Create JWT configuration
let jwt_config = JwtConfig::new_hs256(b"your-secret-key-at-least-32-chars-long!".to_vec())
    .with_issuer("your-app-name")
    .with_metadata(true);

let torii = Torii::new(repositories)
    .with_jwt_sessions(jwt_config);

// Or with custom expiration
let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .with_jwt(jwt_config)
            .expires_in(Duration::hours(2))
    );
```

## Complete Example

Here's a complete example with JWT sessions and password authentication:

```rust,no_run
use std::sync::Arc;
use torii::{Torii, JwtConfig, SessionConfig};
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up database
    let pool = sqlx::SqlitePool::connect("sqlite://auth.db?mode=rwc").await?;
    let repositories = Arc::new(torii::SqliteRepositoryProvider::new(pool));
    repositories.migrate().await?;

    // Configure JWT sessions
    let jwt_config = JwtConfig::new_hs256(
        std::env::var("JWT_SECRET")
            .expect("JWT_SECRET environment variable")
            .as_bytes()
            .to_vec()
    )
    .with_issuer("my-app")
    .with_metadata(true);

    // Create Torii instance
    let torii = Torii::new(repositories)
        .with_session_config(
            SessionConfig::default()
                .with_jwt(jwt_config)
                .expires_in(Duration::hours(24))
        );

    // Register a user
    let user = torii.register_user_with_password("user@example.com", "secure_password").await?;
    println!("User registered: {}", user.id);

    // Verify email (required for login)
    torii.set_user_email_verified(&user.id).await?;

    // Login and create session
    let (user, session) = torii.login_user_with_password(
        "user@example.com",
        "secure_password",
        Some("Mozilla/5.0 (compatible browser)".to_string()),
        Some("192.168.1.100".to_string())
    ).await?;

    println!("Login successful!");
    println!("User: {}", user.id);
    println!("Session token: {}", session.token);
    
    // Validate session
    let validated_session = torii.get_session(&session.token).await?;
    println!("Session valid for user: {}", validated_session.user_id);

    Ok(())
}
```

## Authentication Methods

The example above shows password authentication. Torii supports multiple authentication methods:

- **Password Authentication**: Email/password with secure hashing
- **OAuth/Social Login**: Google, GitHub, and other OAuth providers  
- **Passkey/WebAuthn**: Modern biometric authentication
- **Magic Link**: Passwordless email-based authentication

See the feature flags in your `Cargo.toml` to enable additional authentication methods.

## User Registration

To register a new user with password authentication:

```rust,no_run
use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn register_user(
    torii: &Torii<impl RepositoryProvider>,
    email: &str,
    password: &str
) -> Result<(), ToriiError> {
    // Register a new user
    let user = torii.register_user_with_password(email, password).await?;

    println!("User registered: {}", user.id);
    Ok(())
}
```

## User Login

To authenticate a user with password:

```rust,no_run
use torii::{Torii, ToriiError};
use torii_core::RepositoryProvider;

async fn login_user(
    torii: &Torii<impl RepositoryProvider>,
    email: &str,
    password: &str
) -> Result<(), ToriiError> {
    // Authenticate user - optional user_agent and ip_address for tracking
    let (user, session) = torii.login_user_with_password(
        email, 
        password,
        Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
        Some("127.0.0.1".to_string())
    ).await?;

    // The session token can be stored in a cookie or returned to the client
    println!("User authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}
```

## Session Verification

To verify a user's session token:

```rust,no_run
use torii::{Torii, SessionToken, ToriiError};
use torii_core::RepositoryProvider;

async fn verify_session(
    torii: &Torii<impl RepositoryProvider>,
    session_token: &str
) -> Result<(), ToriiError> {
    // Parse the session token
    let token = SessionToken::new(session_token);
    
    // Verify and get session data (works for both JWT and opaque tokens)
    let session = torii.get_session(&token).await?;

    // Get the user associated with this session
    let user = torii.get_user(&session.user_id).await?
        .ok_or_else(|| ToriiError::AuthError("User not found".to_string()))?;

    println!("Session verified for user: {}", user.id);
    Ok(())
}
```

## OAuth Authentication Flow

For OAuth authentication, you'll need to implement these steps:

1. Generate an authorization URL:

```rust,no_run
use torii::{Torii, ToriiError};

async fn start_oauth_flow(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::OAuthStorage>,
    provider: &str
) -> Result<String, ToriiError> {
    // Get the authorization URL for the provider
    let auth_url = torii.get_oauth_authorization_url(provider).await?;

    // Store the CSRF state in your session/cookies
    let csrf_state = auth_url.csrf_state;

    // Return the URL to redirect the user to
    Ok(auth_url.url)
}
```

2. Handle the OAuth callback:

```rust,no_run
use torii::{Torii, ToriiError};

async fn handle_oauth_callback(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::OAuthStorage>,
    provider: &str,
    code: &str,
    state: &str
) -> Result<(), ToriiError> {
    // Exchange the code for tokens and authenticate the user
    let (user, session) = torii.exchange_oauth_code(
        provider, 
        code, 
        state,
        Some("Browser User Agent".to_string()),
        Some("127.0.0.1".to_string())
    ).await?;

    println!("OAuth user authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}
```

## Passkey Authentication

Passkey (WebAuthn) authentication is performed in two steps:

1. Start registration:

```rust,no_run
use torii::{Torii, ToriiError};

async fn start_passkey_registration(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::PasskeyStorage>,
    email: &str
) -> Result<(), ToriiError> {
    // Begin the passkey registration
    let options = torii.begin_passkey_registration(email).await?;
    
    // Return the challenge ID and WebAuthn options to the client for processing
    println!("Challenge ID: {}", options.challenge_id);
    println!("WebAuthn Options: {}", serde_json::to_string(&options.options).unwrap());
    
    Ok(())
}
```

2. Complete registration:

```rust,no_run
use torii::{Torii, ChallengeId, PasskeyRegistrationCompletion, ToriiError};

async fn complete_passkey_registration(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::PasskeyStorage>,
    email: &str,
    challenge_id: &str,
    response: serde_json::Value
) -> Result<(), ToriiError> {
    // Complete the passkey registration
    let completion = PasskeyRegistrationCompletion {
        email: email.to_string(),
        challenge_id: ChallengeId::new(challenge_id.to_string()),
        response,
    };
    
    let user = torii.complete_passkey_registration(&completion).await?;
    println!("User registered with passkey: {}", user.id);
    
    Ok(())
}
```

## Magic Link Authentication

Magic link authentication is useful for passwordless email-based login:

```rust,no_run
use torii::{Torii, ToriiError};

async fn send_magic_link(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::MagicLinkStorage>,
    email: &str
) -> Result<(), ToriiError> {
    // Generate a magic token
    let token = torii.generate_magic_token(email).await?;
    
    // Create a magic link URL (this would typically be sent via email)
    let magic_link = format!("https://your-app.com/auth/magic-link?token={}", token.token);
    println!("Magic Link: {}", magic_link);
    
    Ok(())
}

async fn verify_magic_link(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::MagicLinkStorage>,
    token: &str
) -> Result<(), ToriiError> {
    // Verify the magic token and create a session
    let (user, session) = torii.verify_magic_token(
        token,
        Some("Browser User Agent".to_string()),
        Some("127.0.0.1".to_string())
    ).await?;
    
    println!("User authenticated via magic link: {}", user.id);
    println!("Session token: {}", session.token);
    
    Ok(())
}
```

## Example Application

You can find a complete example of a Todo application using Torii with Axum in the [examples/todos](https://github.com/cmackenzie1/torii-rs/tree/main/examples/todos) directory. This example demonstrates:

- Setting up Torii with SQLite
- Adding password authentication
- Creating a web server with Axum
- Implementing user registration and login
- Managing authenticated sessions with cookies

## Next Steps

Now that you have a basic understanding of how to use Torii, you can:

- **Learn about [Session Management](./sessions.md)** - Choose between opaque and JWT sessions
- **Configure [JWT Sessions](./sessions/jwt.md)** for stateless authentication
- **Use [Opaque Sessions](./sessions/opaque.md)** for traditional session management
- Integrate Torii with your web framework (Axum, Actix, Rocket, etc.)
- Learn about the [Core Concepts](./core-concepts/index.md) of Users and Sessions
- Explore each authentication method in more depth
- Configure a storage backend for production use

Remember that Torii is designed to give you flexibility while maintaining control over your user data.

## Quick Reference

### JWT Sessions (Stateless)
```rust
let jwt_config = JwtConfig::new_hs256(secret_key.to_vec());
let torii = Torii::new(repositories).with_jwt_sessions(jwt_config);
```

### Opaque Sessions (Stateful - Default)
```rust
let torii = Torii::new(repositories); // Default uses opaque sessions
```

### Environment Variables for Production
```bash
export JWT_SECRET="your-secret-key-at-least-32-characters-long"
export DATABASE_URL="sqlite://production.db"
```
