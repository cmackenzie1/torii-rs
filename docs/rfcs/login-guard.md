# RFC: BruteForceProtection - Account-Based Brute Force Protection

## Summary

Add OWASP-compliant account-based brute force protection to Torii with:
- Per-email login attempt tracking (one row per attempt)
- Automatic account lockout after failed attempts (fixed 15-minute duration)
- Password reset as unlock mechanism
- Full audit trail of failed login attempts
- Background cleanup of old records (protected by `locked_at` timestamp)
- Protection against user enumeration attacks
- Optional opt-out for deployments that don't need lockout

## Motivation

The current IP-based rate limiting (`torii-axum/src/rate_limit.rs`) provides basic protection against automated attacks, but does not fully meet OWASP guidelines. An attacker with multiple IP addresses can still brute force a single account.

OWASP Authentication Cheat Sheet states:
> "The counter of failed logins should be associated with the account itself, rather than the source IP address, in order to prevent an attacker from making login attempts from a large number of different IP addresses."

BruteForceProtection addresses this by tracking failed attempts per email address and locking accounts after too many failures.

## Design

### Data Model

#### `FailedLoginAttempt` Struct

```rust
/// A single failed login attempt record
#[derive(Debug, Clone)]
pub struct FailedLoginAttempt {
    /// Unique identifier
    pub id: i64,
    /// The email that was attempted
    pub email: String,
    /// IP address of the attempt
    pub ip_address: Option<String>,
    /// When the attempt occurred
    pub attempted_at: DateTime<Utc>,
}
```

#### `LockoutStatus` Result Type

```rust
/// Current lockout status for an email
#[derive(Debug, Clone)]
pub struct LockoutStatus {
    /// The email being checked
    pub email: String,
    /// Number of failed attempts in the lockout window
    pub failed_attempts: u32,
    /// Whether the account is currently locked
    pub is_locked: bool,
    /// When the lockout expires (if locked)
    pub locked_until: Option<DateTime<Utc>>,
}
```

#### `BruteForceProtectionConfig` Configuration

```rust
/// Configuration for brute force protection
#[derive(Debug, Clone)]
pub struct BruteForceProtectionConfig {
    /// Whether brute force protection is enabled (default: true)
    pub enabled: bool,
    /// Maximum failed attempts before lockout (default: 5)
    pub max_failed_attempts: u32,
    /// Lockout duration - also used as the window to count attempts (default: 15 minutes)
    /// Failed attempts within this window count toward lockout threshold.
    /// Once locked, the account remains locked for this duration from the last failed attempt.
    pub lockout_period: Duration,
    /// How long to retain attempt records for audit purposes (default: 7 days)
    /// Records are only cleaned up if older than this AND the account is not locked.
    pub retention_period: Duration,
}

impl Default for BruteForceProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_failed_attempts: 5,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        }
    }
}

impl BruteForceProtectionConfig {
    /// Create a disabled configuration (no brute force protection)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}
```

### Database Schema

#### Table: `failed_login_attempts`

Each row represents a single failed login attempt. Lockout is determined by counting recent attempts.

#### Column: `locked_at` on `users` table

A `locked_at` timestamp on the users table prevents accidental cleanup of attempt records while an account is locked. This field is set when an account becomes locked and cleared on unlock.

**SQLite:**
```sql
-- Failed login attempts table
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    ip_address TEXT,
    attempted_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Index for counting attempts by email within a time window
CREATE INDEX idx_failed_login_attempts_email_time ON failed_login_attempts(email, attempted_at);

-- Index for cleanup of old records
CREATE INDEX idx_failed_login_attempts_attempted_at ON failed_login_attempts(attempted_at);

-- Add locked_at to users table
ALTER TABLE users ADD COLUMN locked_at INTEGER;
```

**PostgreSQL:**
```sql
-- Failed login attempts table
CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    email TEXT NOT NULL,
    ip_address TEXT,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for counting attempts by email within a time window
CREATE INDEX idx_failed_login_attempts_email_time ON failed_login_attempts(email, attempted_at);

-- Index for cleanup of old records
CREATE INDEX idx_failed_login_attempts_attempted_at ON failed_login_attempts(attempted_at);

-- Add locked_at to users table
ALTER TABLE users ADD COLUMN locked_at TIMESTAMPTZ;
```

**SeaORM:**
Same structure, managed via SeaORM entities and migrations.

### Repository Trait

```rust
/// Repository for brute force protection
///
/// This trait uses an append-only log of failed attempts.
/// Lockout status is determined by counting recent attempts.
#[async_trait]
pub trait BruteForceProtectionRepository: Send + Sync + 'static {
    /// Record a failed login attempt
    /// Simply inserts a new row; does not check lockout status
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error>;

    /// Get attempt statistics for an email within the given window
    /// Returns count and latest attempt timestamp in a single query
    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error>;

    /// Delete all attempts for an email (on successful login or password reset)
    async fn clear_attempts(&self, email: &str) -> Result<u64, Error>;

    /// Delete attempts older than the given timestamp, but only for unlocked accounts
    /// This prevents cleanup from accidentally unlocking accounts
    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error>;

    /// Set the locked_at timestamp for a user
    async fn set_locked_at(&self, email: &str, locked_at: Option<DateTime<Utc>>) -> Result<(), Error>;

    /// Get the locked_at timestamp for a user
    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error>;
}

/// Statistics about failed login attempts
#[derive(Debug, Clone, Default)]
pub struct AttemptStats {
    /// Number of failed attempts in the window
    pub count: u32,
    /// Timestamp of the most recent attempt (if any)
    pub latest_at: Option<DateTime<Utc>>,
}
```

### Service Layer

```rust
/// Service for managing brute force protection
pub struct BruteForceProtectionService<R: BruteForceProtectionRepository> {
    repository: Arc<R>,
    config: BruteForceProtectionConfig,
}

impl<R: BruteForceProtectionRepository> BruteForceProtectionService<R> {
    /// Create a new BruteForceProtectionService
    pub fn new(repository: Arc<R>, config: BruteForceProtectionConfig) -> Self;

    /// Start the background cleanup task
    /// Returns a JoinHandle for graceful shutdown
    pub fn start_cleanup_task(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()>;

    /// Check if an account is currently locked
    /// Returns the full lockout status including attempt count
    /// Returns immediately with is_locked=false if protection is disabled
    pub async fn get_lockout_status(&self, email: &str) -> Result<LockoutStatus, Error>;

    /// Check if an account is currently locked (convenience method)
    pub async fn is_locked(&self, email: &str) -> Result<bool, Error>;

    /// Record a failed login attempt
    /// Returns the updated lockout status after recording
    /// Emits LoginFailed and optionally AccountLocked events
    /// No-op if protection is disabled
    pub async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<LockoutStatus, Error>;

    /// Clear all attempts for an email (on successful login)
    pub async fn reset_attempts(&self, email: &str) -> Result<(), Error>;

    /// Clear all attempts for an email (on password reset)
    /// Emits AccountUnlocked event if was locked
    pub async fn unlock_account(&self, email: &str) -> Result<(), Error>;
}
```

### Lockout Logic

The lockout check is computed, not stored (except for `locked_at` which protects against cleanup):

```rust
impl<R: BruteForceProtectionRepository> BruteForceProtectionService<R> {
    pub async fn get_lockout_status(&self, email: &str) -> Result<LockoutStatus, Error> {
        // If protection is disabled, always return unlocked
        if !self.config.enabled {
            return Ok(LockoutStatus {
                email: email.to_string(),
                failed_attempts: 0,
                is_locked: false,
                locked_until: None,
            });
        }

        let window_start = Utc::now() - self.config.lockout_period;
        let stats = self.repository.get_attempt_stats(email, window_start).await?;

        // Not enough attempts to trigger lockout
        if stats.count < self.config.max_failed_attempts {
            return Ok(LockoutStatus {
                email: email.to_string(),
                failed_attempts: stats.count,
                is_locked: false,
                locked_until: None,
            });
        }

        // Calculate lockout expiry from the latest attempt
        let locked_until = stats.latest_at.map(|t| t + self.config.lockout_period);
        let is_locked = locked_until.map_or(false, |until| until > Utc::now());

        Ok(LockoutStatus {
            email: email.to_string(),
            failed_attempts: stats.count,
            is_locked,
            locked_until: if is_locked { locked_until } else { None },
        })
    }

    pub async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<LockoutStatus, Error> {
        // If protection is disabled, return unlocked without recording
        if !self.config.enabled {
            return Ok(LockoutStatus {
                email: email.to_string(),
                failed_attempts: 0,
                is_locked: false,
                locked_until: None,
            });
        }

        // Record the attempt
        self.repository.record_failed_attempt(email, ip_address).await?;

        // Get updated status
        let status = self.get_lockout_status(email).await?;

        // If just became locked, set the locked_at timestamp
        if status.is_locked {
            self.repository.set_locked_at(email, Some(Utc::now())).await?;
        }

        Ok(status)
    }

    pub async fn reset_attempts(&self, email: &str) -> Result<(), Error> {
        self.repository.clear_attempts(email).await?;
        self.repository.set_locked_at(email, None).await?;
        Ok(())
    }

    pub async fn unlock_account(&self, email: &str) -> Result<(), Error> {
        let was_locked = self.is_locked(email).await?;
        self.repository.clear_attempts(email).await?;
        self.repository.set_locked_at(email, None).await?;

        if was_locked {
            // Emit AccountUnlocked event
        }

        Ok(())
    }
}
```

### Events

Add to `torii-core/src/events.rs`:

```rust
pub enum AuthEvent {
    // ... existing events ...

    /// Login attempt failed
    LoginFailed {
        email: String,
        failed_attempts: u32,
        ip_address: Option<String>,
        timestamp: DateTime<Utc>,
    },

    /// Account locked due to too many failed attempts
    AccountLocked {
        email: String,
        failed_attempts: u32,
        locked_until: DateTime<Utc>,
        ip_address: Option<String>,
        timestamp: DateTime<Utc>,
    },

    /// Account unlocked (via password reset or expiry)
    AccountUnlocked {
        email: String,
        reason: UnlockReason,
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UnlockReason {
    PasswordReset,
    LockoutExpired,
    AdminAction,
}
```

### Error Types

Add to `torii-core/src/error/mod.rs`:

```rust
#[derive(Debug, Error)]
pub enum AuthError {
    // ... existing variants ...

    #[error("Account is temporarily locked")]
    AccountLocked {
        locked_until: Option<DateTime<Utc>>,
        retry_after_seconds: Option<i64>,
    },
}
```

Add to `torii-axum/src/error.rs`:

```rust
pub enum AuthError {
    // ... existing variants ...

    #[error("Account is temporarily locked")]
    AccountLocked {
        locked_until: Option<DateTime<Utc>>,
        retry_after_seconds: Option<i64>,
    },
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            AuthError::AccountLocked { locked_until, retry_after_seconds } => {
                let retry_after = retry_after_seconds.unwrap_or_else(|| {
                    locked_until
                        .map(|until| (until - Utc::now()).num_seconds().max(0))
                        .unwrap_or(0)
                });

                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "Account is temporarily locked",
                        "retry_after_seconds": retry_after
                    })),
                ).into_response();

                if retry_after > 0 {
                    response.headers_mut().insert(
                        "Retry-After",
                        HeaderValue::from_str(&retry_after.to_string()).unwrap(),
                    );
                }

                response
            }
            // ... other variants ...
        }
    }
}
```

### Integration Points

#### 1. PasswordService Integration

Modify `torii-core/src/services/password.rs`:

```rust
pub async fn authenticate(
    &self,
    email: &str,
    password: &str,
    ip_address: Option<&str>,
) -> Result<User, Error> {
    // 1. Check if account is locked FIRST
    let status = self.brute_force_service.get_lockout_status(email).await?;
    if status.is_locked {
        let retry_after = status.locked_until
            .map(|until| (until - Utc::now()).num_seconds().max(0));
        return Err(Error::Auth(AuthError::AccountLocked {
            locked_until: status.locked_until,
            retry_after_seconds: retry_after,
        }));
    }

    // 2. Attempt authentication
    let result = self.authenticate_internal(email, password).await;

    match result {
        Ok(user) => {
            // Clear failed attempts on success
            self.brute_force_service.reset_attempts(email).await?;
            Ok(user)
        }
        Err(e) if matches!(e, Error::Auth(AuthError::InvalidCredentials)) => {
            // Record failed attempt (also tracks non-existent users)
            let status = self.brute_force_service.record_failed_attempt(email, ip_address).await?;

            // If now locked, return locked error instead
            if status.is_locked {
                let retry_after = status.locked_until
                    .map(|until| (until - Utc::now()).num_seconds().max(0));
                return Err(Error::Auth(AuthError::AccountLocked {
                    locked_until: status.locked_until,
                    retry_after_seconds: retry_after,
                }));
            }

            Err(e)
        }
        Err(e) => Err(e),
    }
}
```

#### 2. Password Reset Integration

Modify `torii-core/src/services/password_reset.rs`:

```rust
pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<User, Error> {
    // ... existing password reset logic ...

    // After successful reset, unlock the account (clears all attempts)
    self.brute_force_service.unlock_account(&user.email).await?;

    Ok(user)
}
```

#### 3. Background Cleanup Task

```rust
impl<R: BruteForceProtectionRepository> BruteForceProtectionService<R> {
    pub fn start_cleanup_task(
        &self,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let repository = Arc::clone(&self.repository);
        let retention = self.config.retention_period;

        // Cleanup runs hourly by default
        const CLEANUP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);

        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(CLEANUP_INTERVAL);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        let before = Utc::now() - retention;
                        match repository.cleanup_old_attempts(before).await {
                            Ok(count) if count > 0 => {
                                tracing::info!("Cleaned up {} old failed login attempt records", count);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to cleanup failed login attempt records: {}", e);
                            }
                            _ => {}
                        }
                    }
                    _ = shutdown.changed() => {
                        tracing::info!("Shutting down brute force protection cleanup task");
                        break;
                    }
                }
            }
        })
    }
}
```

## Usage Example

```rust
use torii::Torii;
use torii_core::BruteForceProtectionConfig;
use chrono::Duration;

// Default configuration (enabled)
let torii = Torii::new(storage)
    .with_brute_force_protection(BruteForceProtectionConfig {
        max_failed_attempts: 3,
        lockout_period: Duration::minutes(30),
        ..Default::default()
    })
    .build()?;

// Disable brute force protection entirely
let torii_no_protection = Torii::new(storage)
    .with_brute_force_protection(BruteForceProtectionConfig::disabled())
    .build()?;

// Or pass None to disable
let torii_no_protection = Torii::new(storage)
    .with_brute_force_protection(None)
    .build()?;

// The protection is automatically integrated with password authentication
let result = torii
    .password_service()
    .authenticate("user@example.com", "password123", Some("192.168.1.1"))
    .await;

match result {
    Ok(user) => println!("Logged in as {}", user.email),
    Err(Error::Auth(AuthError::AccountLocked { retry_after_seconds, .. })) => {
        println!("Account is locked, try again in {} seconds", retry_after_seconds.unwrap_or(0));
    }
    Err(Error::Auth(AuthError::InvalidCredentials)) => {
        println!("Invalid credentials");
    }
    Err(e) => println!("Error: {}", e),
}

// Query attempt history for security monitoring
let status = torii
    .brute_force_protection_service()
    .get_lockout_status("user@example.com")
    .await?;

println!("Failed attempts: {}", status.failed_attempts);
println!("Is locked: {}", status.is_locked);
```

## Design Tradeoffs

### Why Multiple Rows vs Single Row with Counter?

| Aspect | Multiple Rows (chosen) | Single Row with Counter |
|--------|------------------------|-------------------------|
| **Storage** | More rows, but each is small | Single row per email |
| **Audit Trail** | Full history of attempts with timestamps and IPs | Only last attempt info |
| **Analytics** | Easy to query patterns (e.g., "all IPs that hit this account") | Limited |
| **Cleanup** | Simple: DELETE WHERE attempted_at < X AND not locked | Complex: need "resolved" state tracking |
| **Lockout Check** | COUNT query with index | Direct field read |
| **Complexity** | Simpler logic (just INSERT) | Upsert logic required |

The multiple-rows approach was chosen because:
1. Full audit trail is valuable for security investigations
2. Cleanup is trivial (delete old rows for unlocked accounts)
3. No upsert complexity
4. Enables future analytics (attack pattern detection)
5. COUNT with proper index is fast

### Why `locked_at` on Users Table?

The `locked_at` timestamp serves two purposes:
1. **Prevents premature cleanup**: The cleanup task only deletes attempts for accounts that are NOT locked, preventing accidental unlock during cleanup
2. **Fast lockout check**: Can quickly determine if an account might be locked without counting attempts

## Files to Create/Modify

### torii-core

| File | Action | Description |
|------|--------|-------------|
| `src/storage.rs` | Modify | Add `FailedLoginAttempt`, `LockoutStatus`, `AttemptStats` models |
| `src/user.rs` | Modify | Add `locked_at: Option<DateTime<Utc>>` field to `User` |
| `src/repositories/mod.rs` | Modify | Add `BruteForceProtectionRepository` to `RepositoryProvider` trait |
| `src/repositories/brute_force.rs` | **Create** | Define `BruteForceProtectionRepository` trait |
| `src/repositories/adapter.rs` | Modify | Add `BruteForceProtectionRepositoryAdapter` |
| `src/services/mod.rs` | Modify | Export `BruteForceProtectionService`, `BruteForceProtectionConfig` |
| `src/services/brute_force.rs` | **Create** | Implement `BruteForceProtectionService` |
| `src/services/password.rs` | Modify | Integrate lockout checks |
| `src/services/password_reset.rs` | Modify | Unlock on password reset |
| `src/error/mod.rs` | Modify | Add `AccountLocked` error with `retry_after_seconds` |
| `src/events.rs` | Modify | Add login/lockout events |
| `src/lib.rs` | Modify | Export new types |

### torii-storage-seaorm

| File | Action | Description |
|------|--------|-------------|
| `src/entities/mod.rs` | Modify | Add `failed_login_attempt` entity |
| `src/entities/failed_login_attempt.rs` | **Create** | SeaORM entity definition |
| `src/entities/user.rs` | Modify | Add `locked_at` column |
| `src/migrations/mod.rs` | Modify | Register migrations |
| `src/migrations/m20250XXX_000007_create_failed_login_attempts.rs` | **Create** | Create attempts table |
| `src/migrations/m20250XXX_000008_add_locked_at_to_users.rs` | **Create** | Add locked_at column |
| `src/repositories/mod.rs` | Modify | Add to `SeaORMRepositoryProvider` |
| `src/repositories/brute_force.rs` | **Create** | Repository implementation |

### torii-storage-sqlite

| File | Action | Description |
|------|--------|-------------|
| `src/migrations/mod.rs` | Modify | Add migrations for table and column |
| `src/repositories/mod.rs` | Modify | Add to `SqliteRepositoryProvider` |
| `src/repositories/brute_force.rs` | **Create** | Repository implementation |

### torii-storage-postgres

| File | Action | Description |
|------|--------|-------------|
| `src/migrations/mod.rs` | Modify | Add migrations |
| `src/lib.rs` | Modify | Add repository implementation |

### torii

| File | Action | Description |
|------|--------|-------------|
| `src/lib.rs` | Modify | Add `BruteForceProtectionService` to `Torii`, add config method |

### torii-axum

| File | Action | Description |
|------|--------|-------------|
| `src/error.rs` | Modify | Add `AccountLocked` with 429 status + Retry-After header + JSON body |
| `src/routes.rs` | Modify | Pass IP address from request to authentication methods |

## Implementation Order

### Phase 1: Core Types & Trait
1. Add `FailedLoginAttempt`, `LockoutStatus`, `AttemptStats` models to `torii-core/src/storage.rs`
2. Add `locked_at` field to `User` in `torii-core/src/user.rs`
3. Add `BruteForceProtectionConfig` to `torii-core/src/services/brute_force.rs`
4. Add `AccountLocked` error variant with `retry_after_seconds` to `torii-core/src/error/mod.rs`
5. Create `BruteForceProtectionRepository` trait in `torii-core/src/repositories/brute_force.rs`
6. Update `RepositoryProvider` trait in `torii-core/src/repositories/mod.rs`
7. Create `BruteForceProtectionRepositoryAdapter` in `torii-core/src/repositories/adapter.rs`

### Phase 2: Service Layer
8. Add login/lockout events to `torii-core/src/events.rs`
9. Create `BruteForceProtectionService` in `torii-core/src/services/brute_force.rs`
10. Export new types from `torii-core/src/lib.rs` and `torii-core/src/services/mod.rs`

### Phase 3: Storage - SeaORM
11. Create entity `torii-storage-seaorm/src/entities/failed_login_attempt.rs`
12. Create migration for attempts table
13. Create migration to add `locked_at` to users table
14. Create repository `torii-storage-seaorm/src/repositories/brute_force.rs`
15. Update `SeaORMRepositoryProvider`

### Phase 4: Storage - SQLite
16. Add migrations to `torii-storage-sqlite/src/migrations/mod.rs`
17. Create repository `torii-storage-sqlite/src/repositories/brute_force.rs`
18. Update `SqliteRepositoryProvider`

### Phase 5: Storage - PostgreSQL
19. Add migrations to `torii-storage-postgres/src/migrations/mod.rs`
20. Add repository implementation to `torii-storage-postgres/src/lib.rs`

### Phase 6: Integration
21. Modify `PasswordService` to accept `BruteForceProtectionService` and use it
22. Modify `PasswordResetService` to unlock on reset
23. Update `Torii` struct to include `BruteForceProtectionService` and config
24. Add `with_brute_force_protection()` builder method to `Torii` (accepts `Option<Config>`)

### Phase 7: HTTP Layer
25. Add `AccountLocked` error to `torii-axum/src/error.rs` with 429 status
26. Add `Retry-After` header and `retry_after_seconds` in JSON body
27. Pass IP address from request to authentication methods

### Phase 8: Testing
28. Unit tests for `BruteForceProtectionService` (lockout logic, threshold, window)
29. Integration tests for full lockout flow
30. Test password reset unlocking
31. Test cleanup task respects `locked_at`
32. Test non-existent user enumeration protection
33. Test disabled protection (opt-out)
34. Test graceful shutdown of cleanup task

## Security Considerations

1. **User Enumeration Prevention**: Failed attempts are recorded even for non-existent email addresses. The same error response and timing is used regardless of whether the user exists. This prevents attackers from using the lockout mechanism to enumerate valid accounts.

2. **Timing Attacks**: The lockout check happens before password verification. To prevent timing-based enumeration, always verify against a dummy hash when the user doesn't exist, ensuring consistent response times.

3. **DoS via Lockout**: An attacker could intentionally lock out legitimate users. Mitigations:
   - Short lockout duration (15 minutes default)
   - Password reset always works and unlocks the account
   - Consider CAPTCHA integration (future work)

4. **IP Address Storage**: We store IP addresses for each attempt for security monitoring. This data should be considered when implementing data retention policies (GDPR compliance). The cleanup task removes old records automatically.

5. **Error Message Consistency**: Always use generic error messages ("Account is temporarily locked") without revealing the exact unlock time in user-facing responses. The `retry_after_seconds` field is for client convenience, not security.

6. **Table Growth**: The append-only design means the table grows with each failed attempt. The background cleanup task with configurable retention (default 7 days) keeps this manageable. The `locked_at` check ensures cleanup never accidentally unlocks an account.

7. **Race Conditions**: A small race window exists where two concurrent requests could both pass the lockout check. This is acceptable as it only allows one extra attempt beyond the threshold. For stricter enforcement, consider database-level locking (future work).

## Future Work

1. **Magic Link Rate Limiting**: Add per-email rate limiting for magic link requests to prevent "denial by wallet" attacks (email sending costs).

2. **Redis/Memcached Backend**: Implement `BruteForceProtectionRepository` for cache-based storage for better performance at scale.

3. **CAPTCHA Integration**: Add optional CAPTCHA challenge before lockout as an alternative to hard blocking.

4. **Admin Unlock API**: Add administrative endpoint to manually unlock accounts.

5. **Metrics/Monitoring**: Add Prometheus metrics for failed attempts, lockouts, etc.

6. **Attack Pattern Detection**: Use the attempt history to detect distributed attacks (same email from many IPs, or many emails from same IP).

7. **Configurable IP Storage**: Add option to disable or hash IP addresses for privacy compliance.

8. **Database-Level Locking**: Add optional strict mode that uses database locks to prevent any race conditions.

## References

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [Devise Lockable Module](https://github.com/heartcombo/devise/wiki/How-To:-Add-:lockable-to-Users)
- [Spring Security Brute Force Protection](https://www.baeldung.com/spring-security-block-brute-force-authentication-attempts)
