//! Repository trait for brute force protection.
//!
//! This module defines the repository interface for tracking failed login attempts
//! and managing account lockout state.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{
    Error,
    storage::{AttemptStats, FailedLoginAttempt},
};

/// Repository for brute force protection data.
///
/// This trait defines the storage operations needed for tracking failed login
/// attempts and managing account lockout. Implementations should use an append-only
/// log of failed attempts, with lockout status determined by counting recent attempts.
///
/// # Security Considerations
///
/// - Failed attempts should be recorded for all email addresses, even non-existent ones,
///   to prevent user enumeration attacks.
/// - The `cleanup_old_attempts` method must check the `locked_at` status to prevent
///   accidentally unlocking accounts during cleanup.
/// - IP addresses stored for auditing may be subject to data retention regulations.
#[async_trait]
pub trait BruteForceProtectionRepository: Send + Sync + 'static {
    /// Record a failed login attempt.
    ///
    /// Inserts a new row into the failed attempts log. This method does not
    /// check lockout status - that should be done separately.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address that was attempted (may or may not exist)
    /// * `ip_address` - Optional IP address of the client making the attempt
    ///
    /// # Returns
    ///
    /// The created `FailedLoginAttempt` record with its assigned ID and timestamp.
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error>;

    /// Get attempt statistics for an email within a time window.
    ///
    /// Returns the count of failed attempts and the timestamp of the most recent
    /// attempt since the specified cutoff time.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to check
    /// * `since` - Only count attempts after this timestamp
    ///
    /// # Returns
    ///
    /// `AttemptStats` containing the count and latest attempt timestamp.
    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error>;

    /// Delete all attempts for an email address.
    ///
    /// Called on successful login or password reset to clear the attempt history.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to clear attempts for
    ///
    /// # Returns
    ///
    /// The number of records deleted.
    async fn clear_attempts(&self, email: &str) -> Result<u64, Error>;

    /// Delete attempts older than the given timestamp for unlocked accounts only.
    ///
    /// This method is used for periodic cleanup of old records. It must only
    /// delete attempts for accounts that are NOT currently locked (i.e., where
    /// `locked_at` is NULL in the users table for that email).
    ///
    /// # Arguments
    ///
    /// * `before` - Delete attempts with `attempted_at` before this timestamp
    ///
    /// # Returns
    ///
    /// The number of records deleted.
    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error>;

    /// Set the `locked_at` timestamp for a user by email.
    ///
    /// This is called when an account becomes locked (set to `Some(now)`) or
    /// unlocked (set to `None`).
    ///
    /// # Arguments
    ///
    /// * `email` - The email address of the user
    /// * `locked_at` - The timestamp to set, or `None` to clear
    ///
    /// # Note
    ///
    /// This may be a no-op if the user doesn't exist, which is intentional
    /// to prevent user enumeration.
    async fn set_locked_at(
        &self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error>;

    /// Get the `locked_at` timestamp for a user by email.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to check
    ///
    /// # Returns
    ///
    /// `Some(timestamp)` if the user exists and is locked, `None` otherwise.
    /// Returns `None` for non-existent users to prevent enumeration.
    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error>;
}
