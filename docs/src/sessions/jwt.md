# JWT Sessions

JWT (JSON Web Token) sessions provide a stateless authentication mechanism where all session information is encoded within the token itself. This eliminates the need for database lookups during session validation, making it ideal for high-performance applications and microservices.

## When to Use JWT Sessions

JWT sessions are best suited for:

- **Microservices architectures** where session state sharing is complex
- **High-traffic applications** that need fast session validation
- **Distributed systems** without centralized session storage
- **APIs** that serve mobile or SPA clients
- **Scenarios** where session revocation is not critical

## Configuration

### Basic JWT Setup

```rust
use torii::{Torii, JwtConfig};
use chrono::Duration;

// Simple HS256 configuration
let jwt_config = JwtConfig::new_hs256(b"your-secret-key-at-least-32-bytes-long!".to_vec());

let torii = Torii::new(repositories)
    .with_jwt_sessions(jwt_config);
```

**Important:** JWT secret keys must be at least 32 bytes long for HS256. Use `.to_vec()` to convert byte slices to `Vec<u8>` as required by the API.

### Advanced JWT Configuration

```rust
use torii::{Torii, JwtConfig, SessionConfig};
use chrono::Duration;

let jwt_config = JwtConfig::new_hs256(b"your-secret-key-at-least-32-bytes-long!".to_vec())
    .with_issuer("your-application-name")  // Add issuer claim
    .with_metadata(true);                  // Include IP and user agent

let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .with_jwt(jwt_config)
            .expires_in(Duration::hours(2))  // Short-lived for security
    );
```

### RSA Key Configuration

For production environments, RSA keys provide better security:

```rust
use torii::JwtConfig;
use std::fs;

// Load keys from files
let jwt_config = JwtConfig::from_rs256_pem_files(
    "/path/to/private_key.pem",
    "/path/to/public_key.pem"
)?
    .with_issuer("your-app")
    .with_metadata(true);

// Or load keys manually
let private_key = fs::read("/path/to/private_key.pem")?;
let public_key = fs::read("/path/to/public_key.pem")?;
let jwt_config = JwtConfig::new_rs256(private_key, public_key);
```

## JWT Token Structure

When using JWT sessions, Torii creates tokens with the following structure:

### Standard Claims

```json
{
  "sub": "user_123456789",           // Subject (User ID)
  "iat": 1699123456,                // Issued At (Unix timestamp)
  "exp": 1699127056,                // Expiration (Unix timestamp)
  "iss": "your-application-name"    // Issuer (optional)
}
```

### With Metadata Enabled

```json
{
  "sub": "user_123456789",
  "iat": 1699123456,
  "exp": 1699127056,
  "iss": "your-application-name",
  "metadata": {
    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "ip_address": "192.168.1.100"
  }
}
```

## Usage Examples

### Creating JWT Sessions

```rust
use torii::{Torii, UserId, ToriiError};

async fn create_jwt_session(
    torii: &Torii<impl RepositoryProvider>,
    user_id: &UserId,
    user_agent: Option<String>,
    ip_address: Option<String>
) -> Result<String, ToriiError> {
    let session = torii.create_session(user_id, user_agent, ip_address).await?;
    
    // The token is a JWT string
    Ok(session.token.to_string())
}

// Example usage
let user_id = UserId::new("user_123");
let jwt_token = create_jwt_session(
    &torii,
    &user_id,
    Some("Mozilla/5.0 (compatible browser)".to_string()),
    Some("192.168.1.100".to_string())
).await?;

// JWT token looks like: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTY5OTEyMzQ1NiwiZXhwIjoxNjk5MTI3MDU2fQ.signature
```

### Validating JWT Sessions

```rust
use torii::{SessionToken, ToriiError, Session};

async fn validate_jwt_session(
    torii: &Torii<impl RepositoryProvider>,
    jwt_token: &str
) -> Result<Session, ToriiError> {
    let token = SessionToken::new(jwt_token);
    
    // Torii automatically detects this is a JWT and validates it
    let session = torii.get_session(&token).await?;
    
    // Session contains decoded information from the JWT
    println!("User ID: {}", session.user_id);
    println!("Expires at: {}", session.expires_at);
    println!("User agent: {:?}", session.user_agent);
    
    Ok(session)
}
```

### Manual JWT Operations

For advanced use cases, you can work with JWTs directly:

```rust
use torii::{SessionToken, JwtConfig, Session, JwtClaims};

// Create a JWT manually
let jwt_config = JwtConfig::new_hs256(b"your-secret-key-32-bytes-long!!!".to_vec());
let session = Session::builder()
    .user_id(user_id)
    .expires_at(Utc::now() + Duration::hours(2))
    .build()?;

let claims = session.to_jwt_claims(Some("your-app".to_string()), true);
let jwt_token = SessionToken::new_jwt(&claims, &jwt_config)?;

// Verify a JWT manually
let verified_claims = jwt_token.verify_jwt(&jwt_config)?;
println!("User: {}, Expires: {}", verified_claims.sub, verified_claims.exp);
```

## Authentication Middleware Example

Here's how to implement JWT authentication middleware for a web application:

```rust
use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use torii::{Torii, SessionToken, RepositoryProvider};

pub async fn jwt_auth_middleware(
    headers: HeaderMap,
    mut request: Request,
    next: Next
) -> Result<Response, StatusCode> {
    // Extract JWT from Authorization header
    let auth_header = headers.get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Get Torii instance from app state
    let torii: &Torii<impl RepositoryProvider> = request
        .extensions()
        .get()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Validate the JWT session
    let token = SessionToken::new(auth_header);
    let session = torii.get_session(&token).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Add session to request extensions for use in handlers
    request.extensions_mut().insert(session);
    
    Ok(next.run(request).await)
}

// Usage in Axum
use axum::{Router, middleware};

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(middleware::from_fn(jwt_auth_middleware))
    .with_state(torii);
```

## Security Considerations

### Key Management

```rust
// ❌ Bad: Hardcoded secret
let jwt_config = JwtConfig::new_hs256(b"hardcoded-secret".to_vec());

// ✅ Good: Environment variable
let secret = std::env::var("JWT_SECRET")
    .expect("JWT_SECRET environment variable must be set");
let jwt_config = JwtConfig::new_hs256(secret.as_bytes().to_vec());

// ✅ Better: RSA keys for production
let jwt_config = JwtConfig::from_rs256_pem_files(
    std::env::var("JWT_PRIVATE_KEY_PATH")?,
    std::env::var("JWT_PUBLIC_KEY_PATH")?
)?;
```

### Token Expiration

```rust
use chrono::Duration;

// ✅ Short-lived tokens for better security
let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .with_jwt(jwt_config)
            .expires_in(Duration::hours(1))  // 1 hour max
    );
```

### Validation Best Practices

```rust
async fn secure_jwt_validation(
    torii: &Torii<impl RepositoryProvider>,
    token_str: &str,
    expected_issuer: &str,
    max_age_hours: i64
) -> Result<Session, ToriiError> {
    let token = SessionToken::new(token_str);
    let session = torii.get_session(&token).await?;
    
    // Additional validation
    if let SessionToken::Jwt(jwt_str) = &token {
        let config = JwtConfig::new_hs256(get_secret().to_vec());
        let claims = token.verify_jwt(&config)?;
        
        // Validate issuer
        if claims.iss.as_deref() != Some(expected_issuer) {
            return Err(ToriiError::AuthError("Invalid issuer".to_string()));
        }
        
        // Validate token age
        let now = Utc::now().timestamp();
        if now - claims.iat > max_age_hours * 3600 {
            return Err(ToriiError::AuthError("Token too old".to_string()));
        }
    }
    
    Ok(session)
}
```

## Limitations and Considerations

### No Session Revocation

```rust
// ❌ This doesn't actually invalidate JWT tokens
torii.delete_session(&jwt_token).await?;  // This is a no-op for JWTs

// ✅ Workarounds:
// 1. Use short expiration times
// 2. Implement a token blacklist
// 3. Force re-authentication by changing signing keys
```

### Token Size

JWTs are larger than opaque tokens:

```rust
// Opaque token: ~32 characters
// "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"

// JWT token: ~150-300 characters  
// "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzEyMyIsImlhdCI6MTY5OTEyMzQ1NiwiZXhwIjoxNjk5MTI3MDU2fQ.signature"
```

Consider this when:
- Storing tokens in cookies (size limits)
- Sending tokens in headers (HTTP limits)
- Mobile applications (bandwidth considerations)

## Testing JWT Sessions

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use torii::{Torii, JwtConfig};
    use chrono::Duration;

    #[tokio::test]
    async fn test_jwt_session_flow() {
        let repositories = setup_test_repositories().await;
        
        let jwt_config = JwtConfig::new_hs256(b"test-secret-key-32-bytes-long!!!".to_vec())
            .with_issuer("test-app")
            .with_metadata(true);
            
        let torii = Torii::new(repositories)
            .with_jwt_sessions(jwt_config);

        // Create user and session
        let user = torii.register_user_with_password("test@example.com", "password123").await?;
        let session = torii.create_session(
            &user.id,
            Some("Test Agent".to_string()),
            Some("127.0.0.1".to_string())
        ).await?;

        // Verify the token is a JWT
        assert!(session.token.as_str().contains('.'));  // JWTs contain dots
        
        // Validate session
        let validated_session = torii.get_session(&session.token).await?;
        assert_eq!(validated_session.user_id, user.id);
        assert_eq!(validated_session.user_agent, Some("Test Agent".to_string()));
    }
}
```

## RSA Key Generation

To generate RSA keys for production use:

```bash
# Generate private key
openssl genrsa -out private_key.pem 2048

# Generate public key
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Verify the keys
openssl rsa -in private_key.pem -text -noout
```

## Next Steps

- Learn about [Opaque Sessions](./opaque.md) for comparison
- See [Session Management](../sessions.md) for choosing between session types
- Review [Getting Started](../getting-started.md) for complete application examples