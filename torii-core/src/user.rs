//! User management and authentication
//!
//! This module contains the core user struct and related functionality.
//!
//! Users are the core of the authentication system. They are responsible for storing user information and are used to identify users in the system. The core user struct is defined as follows:
//!
//! | Field               | Type               | Description                                       |
//! | ------------------- | ------------------ | ------------------------------------------------- |
//! | `id`                | `String`           | The unique identifier for the user.               |
//! | `name`              | `String`           | The name of the user.                             |
//! | `email`             | `String`           | The email of the user.                            |
//! | `email_verified_at` | `Option<DateTime>` | The timestamp when the user's email was verified. |
//! | `status`            | `UserStatus`       | The status of the user (provisional or active).   |
//! | `created_at`        | `DateTime`         | The timestamp when the user was created.          |
//! | `updated_at`        | `DateTime`         | The timestamp when the user was last updated.     |
use std::str::FromStr;

use crate::{
    Error,
    error::ValidationError,
    id::{generate_prefixed_id, validate_prefixed_id},
    storage::NewUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The status of a user account.
///
/// This enum represents the lifecycle state of a user:
/// - `Provisional`: The user was created via an invitation but has not yet completed signup
/// - `Active`: The user has completed signup and can authenticate
///
/// Provisional users are created when someone is invited to the system. They have a user ID
/// that can be used for references (e.g., sharing resources), but cannot authenticate until
/// they complete the signup process and become active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum UserStatus {
    /// User was invited but has not completed signup
    Provisional,
    /// User has completed signup and can authenticate
    #[default]
    Active,
}

impl UserStatus {
    /// Get the string representation for storage
    pub fn as_str(&self) -> &'static str {
        match self {
            UserStatus::Provisional => "provisional",
            UserStatus::Active => "active",
        }
    }

    /// Check if the user is provisional (invited but not yet signed up)
    pub fn is_provisional(&self) -> bool {
        matches!(self, UserStatus::Provisional)
    }

    /// Check if the user is active (can authenticate)
    pub fn is_active(&self) -> bool {
        matches!(self, UserStatus::Active)
    }
}

impl FromStr for UserStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "provisional" => Ok(UserStatus::Provisional),
            "active" => Ok(UserStatus::Active),
            _ => Err(ValidationError::InvalidField(format!("Invalid user status: {s}")).into()),
        }
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A unique, stable identifier for a specific user
/// This value should be treated as opaque, and should not be used as a UUID even if it may look like one
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: &str) -> Self {
        UserId(id.to_string())
    }

    pub fn new_random() -> Self {
        UserId(generate_prefixed_id("usr"))
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that this ID has the correct format for a user ID
    pub fn is_valid(&self) -> bool {
        validate_prefixed_id(&self.0, "usr")
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new_random()
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for UserId {
    type Err = Error;

    /// Parse a string into a UserId.
    ///
    /// This validates that the string has the correct format for a user ID
    /// (prefixed with "usr_" and containing valid base58-encoded data).
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError::InvalidUserId`] if the string is not a valid user ID format.
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use torii_core::UserId;
    ///
    /// // Valid user ID
    /// let id = UserId::new_random();
    /// let parsed: UserId = id.as_str().parse().unwrap();
    /// assert_eq!(id, parsed);
    ///
    /// // Invalid user ID
    /// let result: Result<UserId, _> = "invalid".parse();
    /// assert!(result.is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = UserId(s.to_string());
        if id.is_valid() {
            Ok(id)
        } else {
            Err(ValidationError::InvalidUserId(format!(
                "Invalid user ID format: expected 'usr_' prefix with valid base58 data, got '{}'",
                s
            ))
            .into())
        }
    }
}

/// The central manager for user operations
///
/// This trait defines core functionality for managing users. Implementations
/// should provide efficient means of creating, retrieving, and updating users.
#[async_trait]
pub trait UserManager: Send + Sync + 'static {
    /// Create a new user
    async fn create_user(&self, user: &NewUser) -> Result<User, Error>;

    /// Get a user by ID
    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Error>;

    /// Get a user by email
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error>;

    /// Get an existing user or create a new one if not found
    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Error>;

    /// Update a user's information
    async fn update_user(&self, user: &User) -> Result<User, Error>;

    /// Delete a user by ID
    async fn delete_user(&self, id: &UserId) -> Result<(), Error>;

    /// Mark a user's email as verified
    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Error>;
}

/// Representation of a user in Torii. This is the user object returned by all authentication plugins.
///
/// Many of these fields are optional, as they may not be available from the authentication provider,
/// or may not be known at the time of authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    // The unique identifier for the user.
    pub id: UserId,

    // The name of the user.
    pub name: Option<String>,

    // The email of the user.
    pub email: String,

    // The email verified at timestamp. If the user has not verified their email, this will be None.
    pub email_verified_at: Option<DateTime<Utc>>,

    /// The status of the user account.
    ///
    /// - `Provisional`: User was created via invitation but hasn't completed signup
    /// - `Active`: User has completed signup and can authenticate
    pub status: UserStatus,

    /// The user ID of whoever invited this user, if applicable.
    ///
    /// This is set when a user is created via an invitation and can be used
    /// for referral tracking or permission inheritance.
    pub invited_by: Option<UserId>,

    /// When the account was locked due to brute force protection.
    ///
    /// This field is set when an account becomes locked after too many failed
    /// login attempts, and cleared when the account is unlocked (via password
    /// reset or admin action). It protects against accidental cleanup of
    /// attempt records while an account is locked.
    pub locked_at: Option<DateTime<Utc>>,

    // The created at timestamp.
    pub created_at: DateTime<Utc>,

    // The updated at timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn builder() -> UserBuilder {
        UserBuilder::default()
    }

    /// Check if the user's email has been verified.
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }

    /// Check if the user account is currently locked.
    ///
    /// Note: This only checks if the `locked_at` timestamp is set. The actual
    /// lockout status should be determined by the `BruteForceProtectionService`
    /// which considers the lockout window and recent failed attempts.
    pub fn is_locked(&self) -> bool {
        self.locked_at.is_some()
    }

    /// Check if the user is provisional (invited but hasn't completed signup).
    pub fn is_provisional(&self) -> bool {
        self.status.is_provisional()
    }

    /// Check if the user is active (can authenticate).
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

#[derive(Default)]
pub struct UserBuilder {
    id: Option<UserId>,
    name: Option<String>,
    email: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    status: Option<UserStatus>,
    invited_by: Option<UserId>,
    locked_at: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl UserBuilder {
    pub fn id(mut self, id: UserId) -> Self {
        self.id = Some(id);
        self
    }

    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub fn email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn email_verified_at(mut self, email_verified_at: Option<DateTime<Utc>>) -> Self {
        self.email_verified_at = email_verified_at;
        self
    }

    pub fn status(mut self, status: UserStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn invited_by(mut self, invited_by: Option<UserId>) -> Self {
        self.invited_by = invited_by;
        self
    }

    pub fn locked_at(mut self, locked_at: Option<DateTime<Utc>>) -> Self {
        self.locked_at = locked_at;
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn build(self) -> Result<User, Error> {
        let now = Utc::now();
        Ok(User {
            id: self.id.unwrap_or_default(),
            name: self.name,
            email: self.email.ok_or(ValidationError::InvalidField(
                "Email is required".to_string(),
            ))?,
            email_verified_at: self.email_verified_at,
            status: self.status.unwrap_or_default(),
            invited_by: self.invited_by,
            locked_at: self.locked_at,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub user_id: UserId,
    pub provider: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthAccount {
    pub fn builder() -> OAuthAccountBuilder {
        OAuthAccountBuilder::default()
    }
}

#[derive(Default)]
pub struct OAuthAccountBuilder {
    user_id: Option<UserId>,
    provider: Option<String>,
    subject: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl OAuthAccountBuilder {
    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn provider(mut self, provider: String) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn build(self) -> Result<OAuthAccount, Error> {
        let now = Utc::now();
        Ok(OAuthAccount {
            user_id: self.user_id.ok_or(ValidationError::MissingField(
                "User ID is required".to_string(),
            ))?,
            provider: self.provider.ok_or(ValidationError::MissingField(
                "Provider is required".to_string(),
            ))?,
            subject: self.subject.ok_or(ValidationError::MissingField(
                "Subject is required".to_string(),
            ))?,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        let user_id = UserId::new("test");
        assert_eq!(user_id.as_str(), "test");

        let user_id_from_str = UserId::from(user_id.as_str());
        assert_eq!(user_id_from_str, user_id);

        let user_id_random = UserId::new_random();
        assert_ne!(user_id_random, user_id);
    }

    #[test]
    fn test_user_id_prefixed() {
        let user_id = UserId::new_random();
        assert!(user_id.as_str().starts_with("usr_"));
        assert!(user_id.is_valid());

        // Test uniqueness
        let user_id2 = UserId::new_random();
        assert_ne!(user_id, user_id2);

        // Test invalid format
        let invalid_id = UserId::new("invalid");
        assert!(!invalid_id.is_valid());

        // Test valid manual creation
        let valid_id = UserId::new("usr_dGVzdA"); // "test" in base64
        assert!(!valid_id.is_valid()); // Should be false because it's too short (not 96 bits)
    }

    #[test]
    fn test_user_id_from_str() {
        // Valid user ID should parse successfully
        let user_id = UserId::new_random();
        let parsed: UserId = user_id.as_str().parse().unwrap();
        assert_eq!(user_id, parsed);

        // Invalid formats should fail
        let invalid_cases = vec![
            "invalid",
            "sess_abc123",
            "usr_",
            "usr_short",
            "",
            "USR_abc123",
        ];

        for invalid in invalid_cases {
            let result: Result<UserId, _> = invalid.parse();
            assert!(result.is_err(), "Expected '{}' to fail parsing", invalid);
        }
    }
}
