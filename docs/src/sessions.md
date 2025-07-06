# Session Management

Torii provides flexible session management through a **session provider architecture** that supports both stateful and stateless sessions. This allows you to choose the session strategy that best fits your application's requirements.

## Session Provider Types

Torii supports two main types of session providers:

### 1. **Opaque Sessions** (Default)
- **Database-backed**: Session data is stored in your database
- **Stateful**: Requires database lookups for validation
- **Revocable**: Can be invalidated immediately by deleting from storage
- **Best for**: Traditional web applications, when you need immediate session revocation

### 2. **JWT Sessions**
- **Self-contained**: All session data is encoded in the token
- **Stateless**: No database lookup required for validation
- **Performant**: Fast validation with no storage overhead
- **Best for**: Microservices, APIs, distributed systems

## Configuration

### Default Configuration (Opaque Sessions)

By default, Torii uses opaque sessions backed by your database:

```rust
use torii::{Torii, SessionConfig};
use chrono::Duration;

let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .expires_in(Duration::days(30))
    );
```

### JWT Sessions

To use JWT sessions, configure Torii with a JWT configuration:

```rust
use torii::{Torii, SessionConfig, JwtConfig};
use chrono::Duration;

// Create JWT configuration
let jwt_config = JwtConfig::new_hs256(b"your-secret-key-at-least-32-chars-long!".to_vec())
    .with_issuer("your-app-name")
    .with_metadata(true); // Include IP and user agent in JWT

let torii = Torii::new(repositories)
    .with_session_config(
        SessionConfig::default()
            .with_jwt(jwt_config)
            .expires_in(Duration::hours(24))
    );

// Or use the convenience method:
let torii = Torii::new(repositories)
    .with_jwt_sessions(jwt_config);
```

## Usage Examples

### Creating Sessions

Session creation works the same regardless of provider type:

```rust
use torii::{Torii, UserId};

// Create a session for a user
let session = torii.create_session(
    &user_id,
    Some("Mozilla/5.0 (compatible browser)".to_string()), // user agent
    Some("192.168.1.100".to_string())                     // IP address
).await?;

println!("Session token: {}", session.token);
```

The session provider determines whether this creates:
- An opaque token (random string) + database record
- A JWT token with embedded session data

### Validating Sessions

Session validation is also transparent:

```rust
use torii::{SessionToken, ToriiError};

async fn authenticate_request(
    torii: &Torii<impl RepositoryProvider>,
    session_token: &str
) -> Result<Session, ToriiError> {
    let token = SessionToken::new(session_token);
    
    // This works for both JWT and opaque tokens
    let session = torii.get_session(&token).await?;
    
    // Session is valid and not expired
    Ok(session)
}
```

For opaque tokens: Torii looks up the session in the database
For JWT tokens: Torii validates the signature and expiration

### Session Termination

```rust
// Delete a specific session
torii.delete_session(&session_token).await?;

// Delete all sessions for a user (useful for "log out everywhere")
torii.delete_sessions_for_user(&user_id).await?;
```

**Note**: For JWT sessions, `delete_session` is a no-op since JWTs are stateless. The tokens remain valid until they expire naturally. To implement JWT revocation, you would need to maintain a blacklist.

## JWT Algorithm Support

Torii supports both symmetric and asymmetric JWT algorithms:

### HMAC with SHA-256 (HS256)

```rust
use torii::JwtConfig;

let jwt_config = JwtConfig::new_hs256(b"your-secret-key-must-be-at-least-32-bytes-long!")
    .with_issuer("your-app")
    .with_metadata(true);
```

### RSA with SHA-256 (RS256)

```rust
use torii::JwtConfig;
use std::fs;

// Load RSA keys from PEM files
let private_key = fs::read("private_key.pem")?;
let public_key = fs::read("public_key.pem")?;

let jwt_config = JwtConfig::new_rs256(private_key, public_key)
    .with_issuer("your-app")
    .with_metadata(true);

// Or load from files directly
let jwt_config = JwtConfig::from_rs256_pem_files(
    "private_key.pem",
    "public_key.pem"
)?;
```

## Session Metadata

When using JWT sessions with metadata enabled, additional information is embedded in the token:

```rust
let jwt_config = JwtConfig::new_hs256(secret_key)
    .with_metadata(true); // Enable metadata

// The resulting JWT will include:
// - User ID (subject)
// - Issued at time
// - Expiration time
// - Issuer (if specified)
// - User agent (if provided during session creation)
// - IP address (if provided during session creation)
```

## Performance Considerations

| Aspect | Opaque Sessions | JWT Sessions |
|--------|----------------|--------------|
| **Creation** | Database write required | CPU-only (signing) |
| **Validation** | Database read required | CPU-only (verification) |
| **Revocation** | Immediate (delete from DB) | Not supported* |
| **Token Size** | Small (~32 chars) | Larger (~150-300 chars) |
| **Horizontal Scaling** | Requires shared database | Fully stateless |
| **Security** | Server-side secrets only | Signature verification |

*JWT revocation requires implementing a token blacklist or short expiration times.

## Security Best Practices

### For Opaque Sessions:
- Use HTTPS to protect tokens in transit
- Implement secure session storage (encrypted at rest)
- Set appropriate session timeouts
- Clear sessions on logout

### For JWT Sessions:
- Use strong signing keys (≥32 bytes for HS256)
- Keep private keys secure and rotated
- Use short expiration times (hours, not days)
- Include `iss` (issuer) claims for validation
- Validate all JWT claims on every request
- Consider token binding to prevent token theft

## Migration Between Session Types

You can change session providers without breaking existing sessions by:

1. **Gradual migration**: Accept both token types during transition
2. **Forced re-authentication**: Require users to log in again
3. **Token conversion**: Convert opaque tokens to JWTs during validation

```rust
// Example: Accept both token types during migration
async fn validate_legacy_session(
    torii: &Torii<impl RepositoryProvider>,
    token_str: &str
) -> Result<Session, ToriiError> {
    let token = SessionToken::new(token_str);
    
    match torii.get_session(&token).await {
        Ok(session) => Ok(session),
        Err(_) => {
            // If modern validation fails, try legacy lookup
            // This allows graceful migration
            fallback_session_validation(token_str).await
        }
    }
}
```

## Common Issues

### "Expected Vec<u8>, found &[u8]" Error

When using HS256 JWT configuration, you may encounter this error:

```rust
// ❌ This will cause a compile error
let jwt_config = JwtConfig::new_hs256(b"my-secret-key");
```

**Solution:** Add `.to_vec()` to convert the byte slice:

```rust
// ✅ This works correctly
let jwt_config = JwtConfig::new_hs256(b"my-secret-key-32-bytes-long!!!".to_vec());
```

### Import Errors

If you can't import `JwtConfig`, ensure you're using the correct path:

```rust
// ✅ Correct import from main crate
use torii::JwtConfig;

// ❌ Don't import from torii_core directly
// use torii_core::JwtConfig;
```

## Next Steps

- Learn more about [JWT Sessions](./sessions/jwt.md)
- Learn more about [Opaque Sessions](./sessions/opaque.md)
- See [Getting Started](./getting-started.md) for complete examples