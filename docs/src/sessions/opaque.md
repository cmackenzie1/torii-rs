# Opaque Sessions

Opaque sessions use random, non-meaningful tokens that reference session data stored in your database. This is the traditional session management approach and Torii's default behavior. The session token itself contains no information - it's just a secure random string used to look up session data.

## When to Use Opaque Sessions

Opaque sessions are best suited for:

- **Traditional web applications** with server-side session management
- **Applications requiring immediate session revocation** (logout, security events)
- **Scenarios with sensitive session metadata** that shouldn't be in tokens
- **Compliance requirements** that mandate server-side session control
- **Applications with long-lived sessions** (weeks/months)

## Configuration

### Default Configuration

Opaque sessions are enabled by default when you create a Torii instance:

```rust
use torii::{Torii, SessionConfig};
use chrono::Duration;

// Default configuration uses opaque sessions
let torii = Torii::new(repositories);

// Explicitly configure opaque sessions with custom expiration
let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .expires_in(Duration::days(30))
    );
```

### Advanced Configuration

```rust
use torii::{Torii, SessionConfig, SessionProviderType};
use chrono::Duration;

// Explicit opaque session configuration
let session_config = SessionConfig {
    expires_in: Duration::days(7),
    provider_type: SessionProviderType::Opaque,
};

let torii = Torii::new(repositories)
    .with_session_config(session_config);
```

## How Opaque Sessions Work

### Session Creation Flow

1. User authenticates successfully
2. Torii generates a cryptographically secure random token
3. Session data is stored in the database with the token as the key
4. The opaque token is returned to the client

```rust
use torii::{Torii, UserId};

async fn create_opaque_session(
    torii: &Torii<impl RepositoryProvider>,
    user_id: &UserId
) -> Result<String, ToriiError> {
    let session = torii.create_session(
        user_id,
        Some("Mozilla/5.0 (compatible browser)".to_string()),
        Some("192.168.1.100".to_string())
    ).await?;
    
    // The token is an opaque string like: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    println!("Opaque token: {}", session.token);
    
    Ok(session.token.to_string())
}
```

### Session Validation Flow

1. Client sends the opaque token
2. Torii looks up the session in the database using the token
3. If found and not expired, the session is valid
4. Session data is returned

```rust
use torii::{SessionToken, Session, ToriiError};

async fn validate_opaque_session(
    torii: &Torii<impl RepositoryProvider>,
    token_str: &str
) -> Result<Session, ToriiError> {
    let token = SessionToken::new(token_str);
    
    // Torii performs a database lookup
    let session = torii.get_session(&token).await?;
    
    // Session contains all stored information
    println!("User ID: {}", session.user_id);
    println!("Created: {}", session.created_at);
    println!("Expires: {}", session.expires_at);
    println!("User Agent: {:?}", session.user_agent);
    println!("IP Address: {:?}", session.ip_address);
    
    Ok(session)
}
```

## Database Schema

Opaque sessions are stored in your database with the following structure:

```sql
-- SQLite example schema
CREATE TABLE sessions (
    token TEXT PRIMARY KEY,           -- The opaque token
    user_id TEXT NOT NULL,           -- Reference to users table
    user_agent TEXT,                 -- Optional user agent string
    ip_address TEXT,                 -- Optional IP address
    created_at DATETIME NOT NULL,    -- Session creation time
    updated_at DATETIME NOT NULL,    -- Last activity time
    expires_at DATETIME NOT NULL,    -- Expiration time
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Index for efficient user lookups
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

## Usage Examples

### Web Application Authentication

```rust
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use torii::{Torii, SessionToken, RepositoryProvider};

// Middleware for session-based authentication
pub async fn session_auth_middleware(
    headers: HeaderMap,
    State(torii): State<Torii<impl RepositoryProvider>>,
    mut request: Request,
    next: Next
) -> Result<Response, StatusCode> {
    // Extract session token from cookie
    let session_token = headers
        .get("cookie")
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str
                .split(';')
                .find(|cookie| cookie.trim().starts_with("session_token="))
                .and_then(|cookie| cookie.split('=').nth(1))
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate the opaque session token
    let token = SessionToken::new(session_token);
    let session = torii.get_session(&token).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Add session to request for use in handlers
    request.extensions_mut().insert(session);
    
    Ok(next.run(request).await)
}
```

### Session Management Operations

```rust
use torii::{Torii, UserId, SessionToken, ToriiError};

// Create a new session
async fn login_user(
    torii: &Torii<impl RepositoryProvider>,
    email: &str,
    password: &str
) -> Result<String, ToriiError> {
    // Authenticate user
    let (user, session) = torii.login_user_with_password(
        email,
        password,
        Some("Browser/1.0".to_string()),
        Some("192.168.1.1".to_string())
    ).await?;
    
    Ok(session.token.to_string())
}

// Logout - immediately invalidate session
async fn logout_user(
    torii: &Torii<impl RepositoryProvider>,
    session_token: &str
) -> Result<(), ToriiError> {
    let token = SessionToken::new(session_token);
    
    // Immediately removes session from database
    torii.delete_session(&token).await?;
    
    Ok(())
}

// Logout from all devices
async fn logout_all_devices(
    torii: &Torii<impl RepositoryProvider>,
    user_id: &UserId
) -> Result<(), ToriiError> {
    // Removes all sessions for this user
    torii.delete_sessions_for_user(user_id).await?;
    
    Ok(())
}

// Clean up expired sessions (run periodically)
async fn cleanup_expired_sessions(
    torii: &Torii<impl RepositoryProvider>
) -> Result<(), ToriiError> {
    torii.session_service.cleanup_expired_sessions().await?;
    
    Ok(())
}
```

### Session Activity Tracking

```rust
use torii::{Session, SessionToken, ToriiError};
use chrono::Utc;

async fn track_session_activity(
    torii: &Torii<impl RepositoryProvider>,
    session_token: &str,
    new_ip: Option<String>
) -> Result<(), ToriiError> {
    let token = SessionToken::new(session_token);
    let mut session = torii.get_session(&token).await?;
    
    // Update session activity
    session.updated_at = Utc::now();
    if let Some(ip) = new_ip {
        session.ip_address = Some(ip);
    }
    
    // Save updated session back to database
    // Note: This requires direct repository access as Torii doesn't 
    // expose session updates through the main API
    
    Ok(())
}
```

## Security Considerations

### Token Generation

Torii generates cryptographically secure random tokens:

```rust
// Torii's token generation (internal implementation)
use rand::{TryRngCore, rngs::OsRng};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

fn generate_secure_token() -> String {
    let mut bytes = vec![0u8; 32]; // 256 bits of entropy
    OsRng.try_fill_bytes(&mut bytes).unwrap();
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}
```

### Session Storage Security

```rust
// Example: Encrypt session data at rest
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

async fn store_encrypted_session(
    session: &Session,
    encryption_key: &[u8; 32]
) -> Result<(), ToriiError> {
    let cipher = Aes256Gcm::new(Key::from_slice(encryption_key));
    let nonce = Nonce::from_slice(b"unique nonce"); // Use unique nonce
    
    let session_data = serde_json::to_vec(session)?;
    let encrypted_data = cipher.encrypt(nonce, session_data.as_ref())
        .map_err(|e| ToriiError::StorageError(e.to_string()))?;
    
    // Store encrypted_data in database
    Ok(())
}
```

### Session Hijacking Prevention

```rust
async fn validate_session_security(
    torii: &Torii<impl RepositoryProvider>,
    token: &SessionToken,
    current_ip: &str,
    current_user_agent: &str
) -> Result<Session, ToriiError> {
    let session = torii.get_session(token).await?;
    
    // Check IP address consistency (optional - can be too strict)
    if let Some(session_ip) = &session.ip_address {
        if session_ip != current_ip {
            // Log suspicious activity
            log::warn!("IP address changed for session: {} -> {}", session_ip, current_ip);
            
            // Optionally invalidate session
            // torii.delete_session(token).await?;
            // return Err(ToriiError::AuthError("Session IP mismatch".to_string()));
        }
    }
    
    // Check user agent consistency
    if let Some(session_ua) = &session.user_agent {
        if session_ua != current_user_agent {
            log::warn!("User agent changed for session");
        }
    }
    
    Ok(session)
}
```

## Performance Optimization

### Database Indexing

```sql
-- Essential indexes for opaque sessions
CREATE INDEX idx_sessions_token ON sessions(token);           -- Primary lookup
CREATE INDEX idx_sessions_user_id ON sessions(user_id);       -- User sessions
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at); -- Cleanup queries

-- Composite index for user session management
CREATE INDEX idx_sessions_user_expires ON sessions(user_id, expires_at);
```

### Connection Pooling

```rust
use sqlx::SqlitePool;
use torii::SqliteRepositoryProvider;

// Use connection pooling for better performance
let pool = SqlitePool::connect_with(
    sqlx::sqlite::SqliteConnectOptions::new()
        .filename("sessions.db")
        .create_if_missing(true)
).await?;

// Configure pool settings
pool.set_max_connections(20);
pool.set_min_connections(5);

let repositories = SqliteRepositoryProvider::new(pool);
```

### Caching Strategy

```rust
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use chrono::{DateTime, Utc};

// Simple in-memory session cache
#[derive(Clone)]
pub struct SessionCache {
    cache: Arc<RwLock<HashMap<String, (Session, DateTime<Utc>)>>>,
    ttl_seconds: u64,
}

impl SessionCache {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl_seconds,
        }
    }
    
    pub fn get(&self, token: &str) -> Option<Session> {
        let cache = self.cache.read().unwrap();
        cache.get(token).and_then(|(session, cached_at)| {
            if Utc::now().signed_duration_since(*cached_at).num_seconds() < self.ttl_seconds as i64 {
                Some(session.clone())
            } else {
                None
            }
        })
    }
    
    pub fn set(&self, token: String, session: Session) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(token, (session, Utc::now()));
    }
}
```

## Monitoring and Analytics

### Session Metrics

```rust
use prometheus::{Counter, Histogram, Gauge};

lazy_static! {
    static ref SESSION_CREATIONS: Counter = Counter::new(
        "torii_sessions_created_total",
        "Total number of sessions created"
    ).expect("metric can be created");
    
    static ref SESSION_VALIDATIONS: Counter = Counter::new(
        "torii_sessions_validated_total", 
        "Total number of session validations"
    ).expect("metric can be created");
    
    static ref SESSION_VALIDATION_DURATION: Histogram = Histogram::new(
        "torii_session_validation_duration_seconds",
        "Time spent validating sessions"
    ).expect("metric can be created");
    
    static ref ACTIVE_SESSIONS: Gauge = Gauge::new(
        "torii_active_sessions",
        "Number of currently active sessions"
    ).expect("metric can be created");
}

async fn monitored_session_validation(
    torii: &Torii<impl RepositoryProvider>,
    token: &SessionToken
) -> Result<Session, ToriiError> {
    let timer = SESSION_VALIDATION_DURATION.start_timer();
    
    let result = torii.get_session(token).await;
    
    timer.observe_duration();
    
    match &result {
        Ok(_) => SESSION_VALIDATIONS.inc(),
        Err(_) => {
            // Track validation failures
            log::warn!("Session validation failed for token");
        }
    }
    
    result
}
```

## Testing Opaque Sessions

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use torii::{Torii, SessionConfig};
    use chrono::Duration;

    #[tokio::test]
    async fn test_opaque_session_lifecycle() {
        let repositories = setup_test_repositories().await;
        
        let torii = Torii::new(repositories)
            .with_session_config(
                SessionConfig::default()
                    .expires_in(Duration::minutes(30))
            );

        // Create user and session
        let user = torii.register_user_with_password("test@example.com", "password123").await?;
        let session = torii.create_session(
            &user.id,
            Some("Test Agent".to_string()),
            Some("127.0.0.1".to_string())
        ).await?;

        // Verify token is opaque (not a JWT)
        assert!(!session.token.as_str().contains('.'));
        assert_eq!(session.token.as_str().len(), 43); // Base64 encoded 32 bytes
        
        // Validate session
        let validated_session = torii.get_session(&session.token).await?;
        assert_eq!(validated_session.user_id, user.id);
        assert_eq!(validated_session.user_agent, Some("Test Agent".to_string()));
        
        // Delete session
        torii.delete_session(&session.token).await?;
        
        // Verify session is gone
        let result = torii.get_session(&session.token).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_session_expiration() {
        let repositories = setup_test_repositories().await;
        
        let torii = Torii::new(repositories)
            .with_session_config(
                SessionConfig::default()
                    .expires_in(Duration::seconds(1))
            );

        let user = torii.register_user_with_password("test@example.com", "password123").await?;
        let session = torii.create_session(&user.id, None, None).await?;
        
        // Session should be valid immediately
        assert!(torii.get_session(&session.token).await.is_ok());
        
        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Session should now be expired
        let result = torii.get_session(&session.token).await;
        assert!(result.is_err());
    }
}
```

## Next Steps

- Learn about [JWT Sessions](./jwt.md) for comparison  
- See [Session Management](../sessions.md) for choosing between session types
- Review [Getting Started](../getting-started.md) for complete application examples
- Explore performance optimization techniques for high-traffic applications