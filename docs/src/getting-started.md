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
torii = { version = "0.2", features = ["password", "sqlite"] }
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
use torii::SqliteStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the storage backend
    let storage = Arc::new(SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?);
    
    // Migrate the storage schema
    storage.migrate().await?;

    // Create a Torii instance with password authentication
    let torii = Torii::new(storage)
        .with_password_plugin();

    // Now torii is ready to use for password-based authentication
    Ok(())
}
```

## Different Initialization Options

Torii provides several ways to initialize the authentication system:

```rust,no_run
use std::sync::Arc;
use torii::Torii;
use torii::SqliteStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?);
    storage.migrate().await?;

    // 1. Simplest approach with a single storage backend
    let torii = Torii::new(storage.clone())
        .with_password_plugin();

    // 2. If you want separate storage for sessions (e.g., Redis):
    // let user_storage = storage.clone();
    // let session_storage = Arc::new(RedisStorage::connect("redis://localhost").await?);
    // let torii = Torii::with_storages(user_storage, session_storage)
    //     .with_password_plugin();

    // 3. If you need custom managers for additional behavior:
    // use torii_core::{DefaultUserManager, DefaultSessionManager, UserManager, SessionManager};
    // let user_manager: Arc<dyn UserManager + Send + Sync> = Arc::new(CustomUserManager::new(storage.clone()));
    // let session_manager: Arc<dyn SessionManager + Send + Sync> = Arc::new(DefaultSessionManager::new(storage.clone()));
    // let torii = Torii::with_managers(storage.clone(), storage.clone(), user_manager, session_manager);

    // 4. If your managers fully encapsulate their storage and you don't need plugins:
    // let user_manager: Arc<dyn UserManager + Send + Sync> = Arc::new(MyUserManager::new(my_db_conn.clone()));
    // let session_manager: Arc<dyn SessionManager + Send + Sync> = Arc::new(RedisSessionManager::new("redis://localhost"));
    // let torii = Torii::<()>::with_custom_managers(user_manager, session_manager);

    Ok(())
}
```

## Adding Multiple Authentication Methods

Torii's plugin system makes it easy to add multiple authentication methods:

```rust,no_run
use torii::{Torii, Provider, SeaORMStorage};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SeaORMStorage::connect("sqlite://auth.db?mode=rwc").await?);
    storage.migrate().await?;

    let torii = Torii::new(storage)
        // Password authentication
        .with_password_plugin()

        // OAuth providers
        .with_oauth_provider(Provider::google(
            "YOUR_GOOGLE_CLIENT_ID",
            "YOUR_GOOGLE_CLIENT_SECRET",
            "https://your-app.com/auth/callback/google"
        ))
        .with_oauth_provider(Provider::github(
            "YOUR_GITHUB_CLIENT_ID",
            "YOUR_GITHUB_CLIENT_SECRET",
            "https://your-app.com/auth/callback/github"
        ))

        // Passkey/WebAuthn
        .with_passkey_plugin(
            "your-app.com",  // Relying Party ID
            "https://your-app.com"  // Relying Party Origin
        )

        // Magic Link authentication
        .with_magic_link_plugin();

    // Now torii is ready to use with multiple authentication methods
    Ok(())
}
```

## Optional JWT Sessions

Torii supports JWT-based sessions for stateless authentication:

```rust,no_run
use torii::{Torii, SqliteStorage, JwtConfig};
use chrono::Duration;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStorage::connect("sqlite://auth.db?mode=rwc").await?);
    storage.migrate().await?;

    // Configure with JWT sessions using HS256 signing
    let jwt_config = JwtConfig::hs256("your-secret-key");
    
    let torii = Torii::new(storage)
        .with_password_plugin()
        .with_jwt_sessions(jwt_config);
    
    // Alternatively, you can configure session expiration
    // let torii = Torii::new(storage)
    //     .with_password_plugin()
    //     .with_session_config(SessionConfig::default().expires_in(Duration::days(7)));

    Ok(())
}
```

## User Registration

To register a new user with password authentication:

```rust,no_run
use torii::{Torii, ToriiError};

async fn register_user(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::PasswordStorage>,
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

async fn login_user(
    torii: &Torii<impl torii_core::storage::UserStorage + torii_core::storage::PasswordStorage>,
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

async fn verify_session(
    torii: &Torii<impl torii_core::storage::UserStorage>,
    session_token: &str
) -> Result<(), ToriiError> {
    // Parse the session token
    let token = SessionToken::new(session_token.to_string());
    
    // Verify and get session data
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

- Integrate Torii with your web framework (Axum, Actix, Rocket, etc.)
- Learn about the core concepts of Users and Sessions
- Explore each authentication method in more depth
- Configure a storage backend for production use

Remember that Torii is designed to give you flexibility while maintaining control over your user data.
