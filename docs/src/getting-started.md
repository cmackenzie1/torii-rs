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
torii = { version = "0.1", features = ["password", "oauth", "passkey", "magic-link", "sqlite"] }
tokio = { version = "1", features = ["full"] }
```

The features you choose will depend on your authentication needs:

- `password`: Email/password authentication
- `oauth`: OAuth/social login support
- `passkey`: WebAuthn/passkey authentication
- `magic-link`: Email magic link authentication
- Storage backend: `sqlite`, `postgres`, or one of the `seaorm-*` variants (e.g. `seaorm-sqlite`, `seaorm-postgres` or `seaorm-mysql`)

## Basic Setup

Here's a minimal example to set up Torii with a SQLite database and password authentication:

```rust,no_run
use std::sync::Arc;
use torii::Torii;
use torii_storage_sqlite::SqliteStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the storage backend
    let storage = Arc::new(SqliteStorage::connect("sqlite:auth.db?mode=rwc").await?);

    // Create a Torii instance with password authentication
    let torii = Torii::new(storage.clone(), storage.clone())
        .with_password_plugin();

    // Now torii is ready to use for password-based authentication
    Ok(())
}
```

## Adding Multiple Authentication Methods

Torii's plugin system makes it easy to add multiple authentication methods:

```rust,no_run
use torii::Torii;
use torii_storage_sqlite::SqliteStorage;
use torii_auth_oauth::providers::Provider;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Arc::new(SqliteStorage::connect("sqlite:auth.db").await?);

    let torii = Torii::new(storage.clone(), storage.clone())
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

## User Registration

To register a new user with password authentication:

```rust,no_run
async fn register_user(
    torii: &Torii<impl UserStorage + PasswordStorage>,
    email: &str,
    password: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Register a new user
    let user = torii.register_user_with_password(email, password).await?;

    println!("User registered: {}", user.id);
    Ok(())
}
```

## User Login

To authenticate a user with password:

```rust,no_run
async fn login_user(
    torii: &Torii<impl UserStorage + PasswordStorage + SessionStorage>,
    email: &str,
    password: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Authenticate user
    let (user, session) = torii.login_user_with_password(email, password).await?;

    // The session token can be stored in a cookie or returned to the client
    println!("User authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}
```

## Session Verification

To verify a user's session token:

```rust,no_run
async fn verify_session(
    torii: &Torii<impl UserStorage + SessionStorage>,
    session_token: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Verify and get session data
    let session = torii.get_session(session_token).await?;

    // Get the user associated with this session
    let user = torii.get_user(&session.user_id).await?;

    println!("Session verified for user: {}", user.id);
    Ok(())
}
```

## OAuth Authentication Flow

For OAuth authentication, you'll need to implement these steps:

1. Generate an authorization URL:

```rust,no_run
async fn start_oauth_flow(
    torii: &Torii<impl UserStorage + OAuthStorage>,
    provider: &str
) -> Result<String, Box<dyn std::error::Error>> {
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
async fn handle_oauth_callback(
    torii: &Torii<impl UserStorage + OAuthStorage + SessionStorage>,
    provider: &str,
    code: &str,
    state: &str
) -> Result<(), Box<dyn std::error::Error>> {
    // Exchange the code for tokens and authenticate the user
    let (user, session) = torii.exchange_oauth_code(provider, code, state).await?;

    println!("OAuth user authenticated: {}", user.id);
    println!("Session token: {}", session.token);

    Ok(())
}
```

## Next Steps

Now that you have a basic understanding of how to use Torii, you can:

- Integrate Torii with your web framework (Axum, Actix, Rocket, etc.)
- Learn about the [User](./core-concepts/users.md) and [Session](./core-concepts/sessions.md) models
- Explore each authentication method in depth
- Configure a [Storage Backend](./storage/index.md) for production use

Check out the remaining documentation for more detailed information on each aspect of Torii.
