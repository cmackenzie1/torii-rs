# Axum Integration

The `torii-axum` crate provides ready-to-use authentication routes and middleware for [Axum](https://github.com/tokio-rs/axum) web applications. It handles all the HTTP concerns while delegating authentication logic to the core `torii` crate.

## Installation

Add the required dependencies to your `Cargo.toml`:

```toml
[dependencies]
torii = { version = "0.5", features = ["password", "magic-link", "mailer"] }
torii-axum = { version = "0.5", features = ["password", "magic-link"] }
torii-storage-seaorm = { version = "0.5" }
axum = "0.8"
tokio = { version = "1", features = ["full"] }
```

### Available Features

The `torii-axum` crate supports these feature flags:

- `password` - Email/password authentication routes
- `magic-link` - Magic link (passwordless) authentication routes
- `oauth` - OAuth authentication routes (coming soon)
- `passkey` - Passkey/WebAuthn routes (coming soon)

## Basic Setup

Here's a minimal example to get authentication routes running:

```rust
use std::sync::Arc;
use axum::Router;
use torii::Torii;
use torii_axum::{routes, CookieConfig, LinkConfig};
use torii_storage_seaorm::SeaORMStorage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set up database
    let storage = SeaORMStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;
    
    // Create Torii instance
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Arc::new(Torii::new(repositories));

    // Create authentication routes
    let auth_routes = routes(torii.clone())
        .with_cookie_config(CookieConfig::development())
        .with_link_config(LinkConfig::new("http://localhost:3000"))
        .build();

    // Build application
    let app = Router::new()
        .nest("/auth", auth_routes)
        .with_state(torii);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## Configuration

### Cookie Configuration

The `CookieConfig` controls how session cookies are set:

```rust
use torii_axum::{CookieConfig, CookieSameSite};

// Development settings (insecure, for local testing)
let config = CookieConfig::development();

// Production settings (secure defaults)
let config = CookieConfig::default();

// Custom configuration
let config = CookieConfig::new("session_id")
    .http_only(true)
    .secure(true)
    .same_site(CookieSameSite::Strict)
    .path("/");
```

| Option | Default | Description |
|--------|---------|-------------|
| `name` | `"session_id"` | Cookie name |
| `http_only` | `true` | Prevents JavaScript access |
| `secure` | `true` | Only sent over HTTPS |
| `same_site` | `Lax` | CSRF protection level |
| `path` | `"/"` | Cookie path |

### Link Configuration

The `LinkConfig` is **required** when using `password` or `magic-link` features. It configures the URLs used in verification emails:

```rust
use torii_axum::LinkConfig;

// Basic setup - uses default path prefix "/auth"
let config = LinkConfig::new("https://example.com");

// Custom path prefix (if you mount auth routes elsewhere)
let config = LinkConfig::new("https://example.com")
    .with_path_prefix("/api/v1/auth");
```

This generates URLs like:
- Magic link: `https://example.com/auth/magic-link/verify?token=...`
- Password reset: `https://example.com/auth/password/reset?token=...`

> **Important**: The `path_prefix` must match where you mount the auth routes in your application. If you use `.nest("/api/v1/auth", auth_routes)`, set `.with_path_prefix("/api/v1/auth")`.

### Email Configuration

To send verification emails, configure a mailer on your Torii instance:

```rust
use torii::Torii;
use torii_mailer::MailerConfig;

// Configure mailer from environment variables
let torii = Torii::new(repositories)
    .with_mailer_from_env()?;

// Or configure manually
let mailer_config = MailerConfig {
    transport: TransportConfig::Smtp {
        host: "smtp.example.com".to_string(),
        port: Some(587),
        username: Some("user".to_string()),
        password: Some("pass".to_string()),
        tls: Some(TlsType::StartTls),
    },
    from_address: "noreply@example.com".to_string(),
    from_name: Some("My App".to_string()),
    app_name: "My App".to_string(),
    app_url: "https://example.com".to_string(),
};

let torii = Torii::new(repositories)
    .with_mailer(mailer_config)?;
```

For local development, emails are saved to `./emails/` by default when no SMTP is configured.

## Available Routes

### Core Routes (always available)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/session` | Get current session |
| `GET` | `/user` | Get current user |
| `POST` | `/logout` | Logout (also `DELETE /session`) |

### Password Routes (feature = "password")

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/register` | Register new user |
| `POST` | `/login` | Login with email/password |
| `POST` | `/password` | Change password (requires auth) |
| `POST` | `/password/reset/request` | Request password reset email |
| `POST` | `/password/reset/verify` | Verify reset token is valid |
| `POST` | `/password/reset/confirm` | Complete password reset |

### Magic Link Routes (feature = "magic-link")

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/magic-link` | Request magic link email |
| `POST` | `/magic-link/verify` | Verify magic link token |

## Request/Response Examples

### Register User

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123"}'
```

Response:
```json
{
  "user": {
    "id": "usr_abc123",
    "email": "user@example.com",
    "name": null,
    "email_verified": false
  },
  "session": {
    "token": "ses_xyz789",
    "user_id": "usr_abc123",
    "expires_at": "2024-01-15T12:00:00Z"
  }
}
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123"}'
```

### Request Magic Link

```bash
curl -X POST http://localhost:3000/auth/magic-link \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

Response:
```json
{
  "message": "Magic link sent to your email"
}
```

The user receives an email with a link like:
`https://example.com/auth/magic-link/verify?token=abc123`

### Verify Magic Link

Your frontend should extract the token from the URL and POST it:

```bash
curl -X POST http://localhost:3000/auth/magic-link/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "abc123"}'
```

### Request Password Reset

```bash
curl -X POST http://localhost:3000/auth/password/reset/request \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
```

Response (always succeeds to prevent email enumeration):
```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

### Complete Password Reset

```bash
curl -X POST http://localhost:3000/auth/password/reset/confirm \
  -H "Content-Type: application/json" \
  -d '{"token": "reset_token_here", "new_password": "newsecurepassword"}'
```

## Authentication Extractors

Use these extractors in your route handlers to access authentication state:

### AuthUser

Requires authentication - returns 401 if not authenticated:

```rust
use torii_axum::AuthUser;

async fn protected_handler(AuthUser(user): AuthUser) -> String {
    format!("Hello, {}!", user.email)
}
```

### OptionalAuthUser

Authentication is optional:

```rust
use torii_axum::OptionalAuthUser;

async fn maybe_protected(OptionalAuthUser(user): OptionalAuthUser) -> String {
    match user {
        Some(u) => format!("Hello, {}!", u.email),
        None => "Hello, guest!".to_string(),
    }
}
```

### Session Token Extractors

For custom authentication logic:

```rust
use torii_axum::{SessionTokenFromCookie, SessionTokenFromBearer, SessionTokenFromRequest};

// From cookie only
async fn from_cookie(SessionTokenFromCookie(token): SessionTokenFromCookie) { }

// From Authorization: Bearer header only
async fn from_bearer(SessionTokenFromBearer(token): SessionTokenFromBearer) { }

// From either cookie or bearer (cookie preferred)
async fn from_either(SessionTokenFromRequest(token): SessionTokenFromRequest) { }
```

## Middleware

### Auth Middleware

Add authentication state to all requests:

```rust
use std::sync::Arc;
use axum::{Router, middleware};
use torii::Torii;
use torii_axum::{auth_middleware, HasTorii};
use torii_storage_seaorm::SeaORMRepositoryProvider;

#[derive(Clone)]
struct AppState {
    torii: Arc<Torii<SeaORMRepositoryProvider>>,
}

impl HasTorii<SeaORMRepositoryProvider> for AppState {
    fn torii(&self) -> &Arc<Torii<SeaORMRepositoryProvider>> {
        &self.torii
    }
}

let state = AppState { torii };

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(middleware::from_fn_with_state(
        state.clone(),
        auth_middleware::<AppState, SeaORMRepositoryProvider>
    ))
    .with_state(state);
```

### Require Auth Middleware

Protect entire route groups:

```rust
use torii_axum::require_auth;

let protected_routes = Router::new()
    .route("/dashboard", get(dashboard))
    .route("/settings", get(settings))
    .layer(middleware::from_fn(require_auth));
```

## Complete Example

Here's a complete example with all features:

```rust
use std::sync::Arc;
use axum::{Router, routing::get, response::Json, middleware};
use torii::Torii;
use torii_axum::{
    routes, AuthUser, OptionalAuthUser, CookieConfig, LinkConfig,
    auth_middleware, HasTorii,
};
use torii_storage_seaorm::SeaORMStorage;

#[derive(Clone)]
struct AppState {
    torii: Arc<Torii<torii_storage_seaorm::SeaORMRepositoryProvider>>,
}

impl HasTorii<torii_storage_seaorm::SeaORMRepositoryProvider> for AppState {
    fn torii(&self) -> &Arc<Torii<torii_storage_seaorm::SeaORMRepositoryProvider>> {
        &self.torii
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Database setup
    let storage = SeaORMStorage::connect("sqlite:./app.db?mode=rwc").await?;
    storage.migrate().await?;
    let repositories = Arc::new(storage.into_repository_provider());
    
    // Torii with email support
    let torii = Arc::new(
        Torii::new(repositories)
            .with_mailer_from_env()
            .unwrap_or_else(|_| Torii::new(repositories.clone()))
    );
    
    let state = AppState { torii: torii.clone() };

    // Auth routes
    let auth_routes = routes(torii)
        .with_cookie_config(CookieConfig::default())
        .with_link_config(LinkConfig::new("https://example.com"))
        .build();

    // Application routes
    let app = Router::new()
        .nest("/auth", auth_routes)
        .route("/", get(home))
        .route("/dashboard", get(dashboard))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware::<AppState, _>
        ))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    println!("Server running on http://localhost:3000");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn home(OptionalAuthUser(user): OptionalAuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Welcome!",
        "authenticated": user.is_some()
    }))
}

async fn dashboard(AuthUser(user): AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.id,
        "email": user.email
    }))
}
```

## Environment Variables

When using `with_mailer_from_env()`, these environment variables are supported:

| Variable | Description | Default |
|----------|-------------|---------|
| `MAILER_SMTP_HOST` | SMTP server hostname | (file transport) |
| `MAILER_SMTP_PORT` | SMTP server port | 587 |
| `MAILER_SMTP_USERNAME` | SMTP username | - |
| `MAILER_SMTP_PASSWORD` | SMTP password | - |
| `MAILER_SMTP_TLS` | TLS mode: `none`, `starttls`, `tls` | `starttls` |
| `MAILER_FROM_ADDRESS` | Sender email address | `noreply@example.com` |
| `MAILER_FROM_NAME` | Sender display name | - |
| `MAILER_APP_NAME` | Application name (in emails) | `Your App` |
| `MAILER_APP_URL` | Application URL (in emails) | `https://example.com` |
| `MAILER_FILE_OUTPUT_DIR` | Directory for file transport | `./emails` |

## Error Handling

All routes return structured JSON errors:

```json
{
  "error": "Invalid credentials",
  "code": 401
}
```

Common error codes:

| Code | Meaning |
|------|---------|
| 400 | Bad request (validation error) |
| 401 | Unauthorized (not authenticated or invalid credentials) |
| 404 | Not found (user or session) |
| 409 | Conflict (email already registered) |
| 500 | Internal server error |

## Next Steps

- Learn about [Core Concepts](./core-concepts/index.md) for deeper understanding
- Explore the [examples](https://github.com/cmackenzie1/torii-rs/tree/main/examples) directory
- Configure production storage backends
- Set up proper email delivery for production
