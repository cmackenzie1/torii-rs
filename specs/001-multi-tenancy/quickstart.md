# Multi-Tenancy Quickstart Guide

**Date**: 2025-10-17  
**Feature**: Multi-Tenancy Support for torii-rs  
**Purpose**: Quick implementation guide for developers

## Overview

This guide shows how to add multi-tenancy support to your torii-rs application. Multi-tenancy allows a single application instance to serve multiple customer organizations (tenants) with complete data isolation.

## Migration from Single-Tenant

### Step 1: Update Dependencies

```toml
[dependencies]
torii = { version = "0.6.0", features = ["sqlite", "password", "multi-tenant"] }
```

### Step 2: Run Database Migration

```rust
use torii::sqlite::SqliteRepositoryProvider;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pool = sqlx::SqlitePool::connect("sqlite://app.db").await?;
    let repositories = SqliteRepositoryProvider::new(pool);
    
    // Run multi-tenant migration (adds tenant_id columns)
    repositories.migrate_to_multi_tenant().await?;
    
    Ok(())
}
```

### Step 3: Update Your Code (Gradual Migration)

**Option A: Keep existing code unchanged (uses default tenant)**
```rust
// Existing code continues to work
let user = torii.register_user("user@example.com", "password").await?;
let (user, session) = torii.authenticate("user@example.com", "password", None, None).await?;
```

**Option B: Migrate to tenant-scoped APIs**
```rust
// New tenant-scoped APIs
let tenant_torii = torii.with_tenant("acme-corp");
let user = tenant_torii.password().register("user@example.com", "password", None).await?;
let (user, session) = tenant_torii.password().authenticate("user@example.com", "password", None, None).await?;
```

## New Multi-Tenant Application

### Basic Setup

```rust
use torii::{Torii, TenantId};
use torii::sqlite::SqliteRepositoryProvider;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup storage
    let pool = sqlx::SqlitePool::connect("sqlite://app.db").await?;
    let repositories = Arc::new(SqliteRepositoryProvider::new(pool));
    
    // Run migrations (includes multi-tenant schema)
    repositories.migrate().await?;
    
    // Create Torii instance
    let torii = Torii::new(repositories);
    
    // Use tenant-scoped operations
    let tenant_id = TenantId::new("acme-corp");
    let tenant_torii = torii.with_tenant(tenant_id);
    
    // Register user in tenant
    let user = tenant_torii.password().register(
        "user@acme.com", 
        "secure_password", 
        Some("John Doe".to_string())
    ).await?;
    
    println!("Created user: {:?}", user);
    
    Ok(())
}
```

### Web Application Integration

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};

// Application state
#[derive(Clone)]
struct AppState {
    torii: Arc<Torii<SqliteRepositoryProvider>>,
}

// Extract tenant from request path
async fn register_user(
    Path(tenant_id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<User>, StatusCode> {
    let tenant_torii = state.torii.with_tenant(tenant_id);
    
    let user = tenant_torii.password().register(
        &payload.email,
        &payload.password,
        payload.name,
    ).await.map_err(|_| StatusCode::BAD_REQUEST)?;
    
    Ok(Json(user))
}

async fn authenticate_user(
    Path(tenant_id): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    let tenant_torii = state.torii.with_tenant(tenant_id);
    
    let (user, session) = tenant_torii.password().authenticate(
        &payload.email,
        &payload.password,
        None,
        None,
    ).await.map_err(|_| StatusCode::UNAUTHORIZED)?;
    
    Ok(Json(AuthResponse { user, session }))
}

// Routes with tenant parameter
fn app_routes() -> Router<AppState> {
    Router::new()
        .route("/tenants/:tenant_id/register", post(register_user))
        .route("/tenants/:tenant_id/login", post(authenticate_user))
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct AuthResponse {
    user: User,
    session: Session,
}
```

## Authentication Methods

### Password Authentication

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Register
let user = tenant_torii.password().register("user@example.com", "password", None).await?;

// Authenticate
let (user, session) = tenant_torii.password().authenticate(
    "user@example.com", 
    "password", 
    Some("Mozilla/5.0...".to_string()),
    Some("192.168.1.1".to_string())
).await?;

// Change password
tenant_torii.password().change_password(&user.id, "old_password", "new_password").await?;
```

### OAuth Authentication

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Find user by OAuth account
let user = tenant_torii.oauth().find_by_provider_account("google", "google_user_id").await?;

// Link OAuth account
tenant_torii.oauth().link_account(&user.id, "google", "google_user_id").await?;

// Authenticate with OAuth
let (user, session) = tenant_torii.oauth().authenticate(
    "google", 
    "google_user_id",
    Some("Mozilla/5.0...".to_string()),
    Some("192.168.1.1".to_string())
).await?;
```

### Passkey Authentication

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Register passkey
let credential = PasskeyCredential::new(/* ... */);
tenant_torii.passkey().register_credential(&user.id, credential).await?;

// Authenticate with passkey
let (user, session) = tenant_torii.passkey().authenticate(
    &credential_id,
    Some("Mozilla/5.0...".to_string()),
    Some("192.168.1.1".to_string())
).await?;

// List user's passkeys
let credentials = tenant_torii.passkey().list_user_credentials(&user.id).await?;
```

### Magic Link Authentication

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Generate magic link
let token = tenant_torii.magic_link().generate_token("user@example.com").await?;

// Send email with magic link (your email service)
send_magic_link_email("user@example.com", &token.token).await?;

// Authenticate with magic link
let (user, session) = tenant_torii.magic_link().authenticate(
    &token.token,
    Some("Mozilla/5.0...".to_string()),
    Some("192.168.1.1".to_string())
).await?;
```

## Session Management

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Create session
let session = tenant_torii.create_session(&user, None, None).await?;

// Validate session
let session = tenant_torii.validate_session(&session.token).await?;

// List user sessions
let sessions = tenant_torii.list_user_sessions(&user.id).await?;

// Revoke session
tenant_torii.revoke_session(&session.token).await?;
```

## User Management

```rust
let tenant_torii = torii.with_tenant("acme-corp");

// Get user by ID
let user = tenant_torii.get_user(&user_id).await?;

// Get user by email
let user = tenant_torii.get_user_by_email("user@example.com").await?;

// List all users in tenant
let users = tenant_torii.list_users().await?;
```

## Error Handling

```rust
use torii::{ToriiError, TenantError};

match tenant_torii.get_user(&user_id).await {
    Ok(Some(user)) => println!("Found user: {:?}", user),
    Ok(None) => println!("User not found in this tenant"),
    Err(ToriiError::Tenant(TenantError::CrossTenantAccess)) => {
        println!("User belongs to different tenant");
    }
    Err(e) => println!("Error: {:?}", e),
}
```

## Best Practices

### 1. Tenant Context Management
```rust
// Extract tenant from request early
fn extract_tenant_id(request: &Request) -> Result<TenantId, Error> {
    // From subdomain: acme.myapp.com -> "acme"
    // From path: /tenants/acme/users -> "acme"
    // From header: X-Tenant-ID -> "acme"
}

// Use throughout request lifecycle
let tenant_torii = torii.with_tenant(tenant_id);
```

### 2. Error Handling
```rust
// Always handle tenant-specific errors
match result {
    Err(ToriiError::Tenant(TenantError::UserNotInTenant { .. })) => {
        return Err(StatusCode::NOT_FOUND);
    }
    Err(ToriiError::Tenant(TenantError::CrossTenantAccess)) => {
        return Err(StatusCode::FORBIDDEN);
    }
    // ... other errors
}
```

### 3. Performance Optimization
```rust
// Use tenant-scoped queries for better performance
let users = tenant_torii.list_users().await?; // Automatically filtered by tenant

// Avoid cross-tenant operations
// DON'T: torii.get_user(&user_id) // Could return user from any tenant
// DO: tenant_torii.get_user(&user_id) // Only returns user from this tenant
```

### 4. Testing
```rust
#[tokio::test]
async fn test_tenant_isolation() {
    let torii = setup_test_torii().await;
    
    // Create users in different tenants
    let tenant_a = torii.with_tenant("tenant-a");
    let tenant_b = torii.with_tenant("tenant-b");
    
    let user_a = tenant_a.password().register("user@example.com", "password", None).await?;
    let user_b = tenant_b.password().register("user@example.com", "password", None).await?;
    
    // Verify isolation
    assert!(tenant_a.get_user(&user_b.id).await?.is_none());
    assert!(tenant_b.get_user(&user_a.id).await?.is_none());
}
```

## Migration Checklist

- [ ] Update torii dependency to version with multi-tenant support
- [ ] Run database migration: `repositories.migrate_to_multi_tenant().await?`
- [ ] Update application code to use tenant-scoped APIs
- [ ] Add tenant extraction logic to your web framework
- [ ] Update error handling for tenant-specific errors
- [ ] Add tests for tenant isolation
- [ ] Update documentation and deployment guides
