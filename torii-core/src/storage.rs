use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use secrecy::{ExposeSecret, SecretString};

use crate::{
    Error, OAuthAccount, Session, User, UserId, error::utilities::RequiredFieldExt,
    session::SessionToken,
};

// ============================================================================
// Brute Force Protection Types
// ============================================================================

/// A single failed login attempt record.
///
/// Each record represents one failed authentication attempt against an email address.
/// These records are used to track brute force attacks and implement account lockout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedLoginAttempt {
    /// Unique identifier for this attempt record
    pub id: i64,
    /// The email address that was attempted (may or may not exist in the system)
    pub email: String,
    /// IP address of the client that made the attempt (if available)
    pub ip_address: Option<String>,
    /// When the attempt occurred
    pub attempted_at: DateTime<Utc>,
}

/// Current lockout status for an email address.
///
/// This struct represents the computed lockout state based on recent failed attempts.
/// The lockout is calculated dynamically rather than stored, allowing for automatic
/// expiry without background cleanup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockoutStatus {
    /// The email address being checked
    pub email: String,
    /// Number of failed attempts within the lockout window
    pub failed_attempts: u32,
    /// Whether the account is currently locked
    pub is_locked: bool,
    /// When the lockout expires (if locked)
    pub locked_until: Option<DateTime<Utc>>,
}

impl LockoutStatus {
    /// Returns the number of seconds until the lockout expires.
    ///
    /// Returns `None` if the account is not locked, or `Some(0)` if the
    /// lockout has already expired.
    pub fn retry_after_seconds(&self) -> Option<i64> {
        self.locked_until.map(|until| {
            let seconds = (until - Utc::now()).num_seconds();
            seconds.max(0)
        })
    }
}

/// Statistics about failed login attempts for an email address.
///
/// This struct is returned by the repository and contains the raw data
/// needed to compute lockout status.
#[derive(Debug, Clone, Default)]
pub struct AttemptStats {
    /// Number of failed attempts in the counting window
    pub count: u32,
    /// Timestamp of the most recent attempt (if any)
    pub latest_at: Option<DateTime<Utc>>,
}

/// Configuration for brute force protection.
///
/// This configuration controls how account lockout behaves, including
/// the threshold for lockout, duration, and retention of audit records.
///
/// # Example
///
/// ```
/// use torii_core::storage::BruteForceProtectionConfig;
/// use chrono::Duration;
///
/// // Default configuration (enabled with 5 attempts, 15 minute lockout)
/// let config = BruteForceProtectionConfig::default();
///
/// // Custom configuration
/// let config = BruteForceProtectionConfig {
///     max_failed_attempts: 3,
///     lockout_period: Duration::minutes(30),
///     ..Default::default()
/// };
///
/// // Disable brute force protection entirely
/// let disabled = BruteForceProtectionConfig::disabled();
/// ```
#[derive(Debug, Clone)]
pub struct BruteForceProtectionConfig {
    /// Whether brute force protection is enabled.
    ///
    /// When disabled, no failed attempts are recorded and lockout checks
    /// always return unlocked.
    pub enabled: bool,

    /// Maximum failed attempts before lockout.
    ///
    /// Once this threshold is reached within the lockout window,
    /// the account becomes locked.
    pub max_failed_attempts: u32,

    /// Lockout duration and counting window.
    ///
    /// Failed attempts within this window count toward the lockout threshold.
    /// Once locked, the account remains locked for this duration from the
    /// last failed attempt.
    pub lockout_period: Duration,

    /// How long to retain attempt records for audit purposes.
    ///
    /// Records older than this are eligible for cleanup, but only if the
    /// associated account is not currently locked.
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
    /// Create a disabled configuration (no brute force protection).
    ///
    /// Use this when deploying in environments where account lockout
    /// is not desired or is handled by other means.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

// ============================================================================
// Legacy Storage Traits
// ============================================================================
//
// NOTE: These traits are maintained for compatibility with existing storage
// backend implementations. New storage backends should implement the
// Repository traits in `crate::repositories` instead.
//
// The Repository traits provide a cleaner, more composable API.

#[async_trait]
pub trait StoragePlugin: Send + Sync + 'static {
    type Config;

    /// Initialize storage with config
    async fn initialize(&self, config: Self::Config) -> Result<(), Error>;

    /// Storage health check
    async fn health_check(&self) -> Result<(), Error>;

    /// Clean up expired data
    async fn cleanup(&self) -> Result<(), Error>;
}

/// User storage trait for legacy storage backends.
///
/// For new implementations, consider using [`crate::repositories::UserRepository`] instead.
#[async_trait]
pub trait UserStorage: Send + Sync + 'static {
    async fn create_user(&self, user: &NewUser) -> Result<User, Error>;
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Error>;
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error>;
    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Error>;
    async fn update_user(&self, user: &User) -> Result<User, Error>;
    async fn delete_user(&self, id: &UserId) -> Result<(), Error>;
    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Error>;
}

/// Session storage trait used by [`crate::session::OpaqueSessionProvider`].
///
/// This trait is implemented by the [`crate::repositories::adapter::SessionRepositoryAdapter`]
/// to bridge between Repository-based storage backends and the session provider system.
#[async_trait]
pub trait SessionStorage: Send + Sync + 'static {
    async fn create_session(&self, session: &Session) -> Result<Session, Error>;
    async fn get_session(&self, token: &SessionToken) -> Result<Option<Session>, Error>;
    async fn delete_session(&self, token: &SessionToken) -> Result<(), Error>;
    async fn cleanup_expired_sessions(&self) -> Result<(), Error>;
    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error>;
}

/// Password storage trait for legacy storage backends.
///
/// For new implementations, consider using [`crate::repositories::PasswordRepository`] instead.
#[async_trait]
pub trait PasswordStorage: UserStorage {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error>;
}

/// OAuth storage trait for legacy storage backends.
///
/// For new implementations, consider using [`crate::repositories::OAuthRepository`] instead.
#[async_trait]
pub trait OAuthStorage: UserStorage {
    /// Create a new OAuth account linked to a user
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error>;

    /// Find a user by their OAuth provider and subject
    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error>;

    /// Find an OAuth account by provider and subject
    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error>;

    /// Link an existing user to an OAuth account
    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error>;

    /// Store a PKCE verifier with an expiration time
    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Error>;

    /// Retrieve a stored PKCE verifier by CSRF state
    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewUser {
    pub id: UserId,
    pub email: String,
    pub name: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
}

impl NewUser {
    pub fn builder() -> NewUserBuilder {
        NewUserBuilder::default()
    }

    pub fn new(email: String) -> Self {
        NewUserBuilder::default()
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }

    pub fn with_id(id: UserId, email: String) -> Self {
        NewUserBuilder::default()
            .id(id)
            .email(email)
            .build()
            .expect("Default builder should never fail")
    }
}

#[derive(Default)]
pub struct NewUserBuilder {
    id: Option<UserId>,
    email: Option<String>,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
}

impl NewUserBuilder {
    pub fn id(mut self, id: UserId) -> Self {
        self.id = Some(id);
        self
    }

    pub fn email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    pub fn email_verified_at(mut self, email_verified_at: Option<DateTime<Utc>>) -> Self {
        self.email_verified_at = email_verified_at;
        self
    }

    pub fn build(self) -> Result<NewUser, Error> {
        Ok(NewUser {
            id: self.id.unwrap_or_default(),
            email: self.email.require_field("Email")?,
            name: self.name,
            email_verified_at: self.email_verified_at,
        })
    }
}

/// Storage methods specific to passkey authentication
///
/// This trait extends the base `UserStorage` trait with methods needed for
/// storing and retrieving passkey credentials for a user.
#[async_trait]
pub trait PasskeyStorage: UserStorage {
    /// Add a passkey credential for a user
    async fn add_passkey(
        &self,
        user_id: &UserId,
        credential_id: &str,
        passkey_json: &str,
    ) -> Result<(), Error>;

    /// Get a passkey by credential ID
    async fn get_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, Error>;

    /// Get all passkeys for a user
    async fn get_passkeys(&self, user_id: &UserId) -> Result<Vec<String>, Error>;

    /// Set a passkey challenge for a user
    async fn set_passkey_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Error>;

    /// Get a passkey challenge
    async fn get_passkey_challenge(&self, challenge_id: &str) -> Result<Option<String>, Error>;
}

/// Purpose enumeration for secure tokens to ensure type safety
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenPurpose {
    /// Tokens used for magic link authentication
    MagicLink,
    /// Tokens used for password reset flows
    PasswordReset,
    /// Tokens used for email verification (future)
    EmailVerification,
}

impl TokenPurpose {
    /// Get the string representation of the token purpose for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenPurpose::MagicLink => "magic_link",
            TokenPurpose::PasswordReset => "password_reset",
            TokenPurpose::EmailVerification => "email_verification",
        }
    }
}

impl FromStr for TokenPurpose {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use crate::error::StorageError;
        match s {
            "magic_link" => Ok(TokenPurpose::MagicLink),
            "password_reset" => Ok(TokenPurpose::PasswordReset),
            "email_verification" => Ok(TokenPurpose::EmailVerification),
            _ => Err(Error::Storage(StorageError::Database(format!(
                "Invalid token purpose: {s}"
            )))),
        }
    }
}

/// Generic secure token for various authentication purposes
///
/// # Security
///
/// This struct separates the plaintext token (sent to the user) from the token hash
/// (stored in the database) to prevent timing attacks during token verification.
/// The `token_hash` field contains a SHA256 hash that should be stored in the database,
/// while `token` contains the plaintext value that is only returned to the user.
///
/// The plaintext token is wrapped in `SecretString` to prevent accidental exposure
/// in logs or debug output. Use `expose_secret()` to access the value when needed.
///
/// When loading tokens from storage, the `token` field will be `None` since only
/// the hash is stored. Verification should be done using [`crate::crypto::verify_token_hash`].
#[derive(Clone)]
pub struct SecureToken {
    pub user_id: UserId,
    /// The plaintext token value (only set when creating a new token, not when loading from storage)
    /// Wrapped in SecretString to prevent accidental logging
    token: Option<SecretString>,
    /// The SHA256 hash of the token (stored in database for secure verification)
    pub token_hash: String,
    pub purpose: TokenPurpose,
    pub used_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SecureToken {
    /// Create a new SecureToken with both plaintext and hash
    ///
    /// This constructor is used when creating a new token where both
    /// the plaintext (to return to user) and hash (to store) are available.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user_id: UserId,
        token: String,
        token_hash: String,
        purpose: TokenPurpose,
        used_at: Option<DateTime<Utc>>,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            token: Some(SecretString::from(token)),
            token_hash,
            purpose,
            used_at,
            expires_at,
            created_at,
            updated_at,
        }
    }

    /// Create a SecureToken from stored data (hash only, no plaintext)
    ///
    /// This constructor is used when loading a token from storage where
    /// only the hash is available (plaintext is never stored).
    pub fn from_storage(
        user_id: UserId,
        token_hash: String,
        purpose: TokenPurpose,
        used_at: Option<DateTime<Utc>>,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            user_id,
            token: None, // Plaintext not available from storage
            token_hash,
            purpose,
            used_at,
            expires_at,
            created_at,
            updated_at,
        }
    }

    pub fn used(&self) -> bool {
        self.used_at.is_some()
    }

    /// Get the plaintext token value.
    ///
    /// This is only available when the token was just created.
    /// Returns `None` when the token was loaded from storage.
    pub fn token(&self) -> Option<&str> {
        self.token.as_ref().map(|s| s.expose_secret())
    }

    /// Verify a plaintext token against this token's hash using constant-time comparison
    ///
    /// This method uses SHA256 and constant-time comparison to prevent timing attacks.
    pub fn verify(&self, token: &str) -> bool {
        crate::crypto::verify_token_hash(token, &self.token_hash)
    }
}

impl std::fmt::Debug for SecureToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureToken")
            .field("user_id", &self.user_id)
            .field("token", &"[REDACTED]")
            .field("token_hash", &self.token_hash)
            .field("purpose", &self.purpose)
            .field("used_at", &self.used_at)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl PartialEq for SecureToken {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
            && self.token_hash == other.token_hash
            && self.purpose == other.purpose
            && self.used_at == other.used_at
            // Some databases may not store the timestamp with more precision than seconds, so we compare the timestamps as integers
            && self.expires_at.timestamp() == other.expires_at.timestamp()
            && self.created_at.timestamp() == other.created_at.timestamp()
            && self.updated_at.timestamp() == other.updated_at.timestamp()
    }
}

/// Storage methods for secure tokens
///
/// This trait provides storage for generic secure tokens that can be used
/// for various authentication purposes like magic links, password resets, and email verification.
///
/// # Security
///
/// Token storage uses SHA256 hashed tokens. Since tokens are generated with
/// 256 bits of entropy, SHA256 provides sufficient security for storage.
/// Verification is done using constant-time comparison via [`crate::crypto::verify_token_hash`].
///
/// Lookups are performed by hash, avoiding the need to iterate over all tokens.
#[async_trait]
pub trait TokenStorage: UserStorage {
    /// Save a secure token to storage
    ///
    /// The token's `token_hash` field should be stored (not the plaintext token).
    async fn save_secure_token(&self, token: &SecureToken) -> Result<(), Error>;

    /// Get a token by its hash
    ///
    /// Returns the token if found and valid (unexpired, unused), None otherwise.
    /// The caller should use constant-time comparison to verify the token.
    async fn get_token_by_hash(
        &self,
        token_hash: &str,
        purpose: TokenPurpose,
    ) -> Result<Option<SecureToken>, Error>;

    /// Mark a secure token as used by its hash
    ///
    /// After successful verification, call this to mark the token as consumed.
    async fn set_secure_token_used_by_hash(
        &self,
        token_hash: &str,
        purpose: TokenPurpose,
    ) -> Result<(), Error>;

    /// Clean up expired tokens for all purposes
    async fn cleanup_expired_secure_tokens(&self) -> Result<(), Error>;
}
