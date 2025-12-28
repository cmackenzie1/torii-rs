//! Brute force protection service for account-based lockout.
//!
//! This module implements OWASP-compliant account-based brute force protection
//! with per-email login attempt tracking and automatic account lockout.
//!
//! # Features
//!
//! - Per-email login attempt tracking
//! - Automatic account lockout after configurable failed attempts
//! - Password reset as unlock mechanism
//! - Full audit trail of failed login attempts
//! - Background cleanup of old records
//! - Protection against user enumeration attacks
//!
//! # Example
//!
//! ```rust,ignore
//! use torii_core::services::BruteForceProtectionService;
//! use torii_core::storage::BruteForceProtectionConfig;
//!
//! let service = BruteForceProtectionService::new(
//!     repository,
//!     BruteForceProtectionConfig::default(),
//! );
//!
//! // Check if account is locked before authentication
//! let status = service.get_lockout_status("user@example.com").await?;
//! if status.is_locked {
//!     // Return appropriate error to client
//! }
//!
//! // Record failed attempt after authentication failure
//! let status = service.record_failed_attempt("user@example.com", Some("192.168.1.1")).await?;
//! ```

use std::sync::Arc;

use chrono::Utc;

use crate::{
    Error,
    repositories::BruteForceProtectionRepository,
    storage::{AttemptStats, BruteForceProtectionConfig, LockoutStatus},
};

/// Service for managing brute force protection.
///
/// This service coordinates between the repository layer and the application,
/// providing high-level operations for tracking failed login attempts and
/// managing account lockout state.
///
/// # Thread Safety
///
/// This service is thread-safe and can be shared across multiple tasks.
/// The underlying repository handles concurrent access appropriately.
pub struct BruteForceProtectionService<R: BruteForceProtectionRepository> {
    repository: Arc<R>,
    config: BruteForceProtectionConfig,
}

impl<R: BruteForceProtectionRepository> BruteForceProtectionService<R> {
    /// Create a new BruteForceProtectionService.
    ///
    /// # Arguments
    ///
    /// * `repository` - The repository implementation for storing attempt data
    /// * `config` - Configuration for lockout behavior
    pub fn new(repository: Arc<R>, config: BruteForceProtectionConfig) -> Self {
        Self { repository, config }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &BruteForceProtectionConfig {
        &self.config
    }

    /// Check if brute force protection is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the current lockout status for an email address.
    ///
    /// This method computes the lockout state based on recent failed attempts.
    /// If protection is disabled, it always returns an unlocked status.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to check
    ///
    /// # Returns
    ///
    /// The current `LockoutStatus` for the email address.
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
        let stats = self
            .repository
            .get_attempt_stats(email, window_start)
            .await?;

        self.compute_lockout_status(email, &stats)
    }

    /// Check if an account is currently locked (convenience method).
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to check
    ///
    /// # Returns
    ///
    /// `true` if the account is locked, `false` otherwise.
    pub async fn is_locked(&self, email: &str) -> Result<bool, Error> {
        Ok(self.get_lockout_status(email).await?.is_locked)
    }

    /// Record a failed login attempt.
    ///
    /// This method records the attempt and returns the updated lockout status.
    /// If the account becomes locked as a result, it sets the `locked_at` timestamp
    /// on the user record to protect against premature cleanup.
    ///
    /// If protection is disabled, this is a no-op that returns an unlocked status.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address that was attempted (may or may not exist)
    /// * `ip_address` - Optional IP address of the client
    ///
    /// # Returns
    ///
    /// The updated `LockoutStatus` after recording the attempt.
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
        self.repository
            .record_failed_attempt(email, ip_address)
            .await?;

        // Get updated status
        let status = self.get_lockout_status(email).await?;

        // If just became locked, set the locked_at timestamp to protect against cleanup
        if status.is_locked {
            self.repository
                .set_locked_at(email, Some(Utc::now()))
                .await?;
        }

        Ok(status)
    }

    /// Clear all attempts for an email address on successful login.
    ///
    /// This should be called after a successful authentication to reset
    /// the failed attempt counter and clear the locked_at timestamp.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to reset
    pub async fn reset_attempts(&self, email: &str) -> Result<(), Error> {
        self.repository.clear_attempts(email).await?;
        self.repository.set_locked_at(email, None).await?;
        Ok(())
    }

    /// Unlock an account (e.g., after password reset).
    ///
    /// This clears all failed attempts and the locked_at timestamp,
    /// effectively unlocking the account regardless of its previous state.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to unlock
    ///
    /// # Returns
    ///
    /// `true` if the account was previously locked, `false` otherwise.
    pub async fn unlock_account(&self, email: &str) -> Result<bool, Error> {
        let was_locked = self.is_locked(email).await?;
        self.repository.clear_attempts(email).await?;
        self.repository.set_locked_at(email, None).await?;
        Ok(was_locked)
    }

    /// Start the background cleanup task.
    ///
    /// This spawns a task that periodically cleans up old failed attempt records.
    /// Records are only deleted if they are older than the retention period AND
    /// the associated account is not currently locked.
    ///
    /// # Arguments
    ///
    /// * `shutdown` - A watch receiver that signals when to stop the task
    ///
    /// # Returns
    ///
    /// A `JoinHandle` for the spawned task.
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
                                tracing::info!(
                                    count = count,
                                    "Cleaned up old failed login attempt records"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    "Failed to cleanup failed login attempt records"
                                );
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

    /// Compute lockout status from attempt statistics.
    fn compute_lockout_status(
        &self,
        email: &str,
        stats: &AttemptStats,
    ) -> Result<LockoutStatus, Error> {
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
        let is_locked = locked_until.is_some_and(|until| until > Utc::now());

        Ok(LockoutStatus {
            email: email.to_string(),
            failed_attempts: stats.count,
            is_locked,
            locked_until: if is_locked { locked_until } else { None },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::FailedLoginAttempt;
    use async_trait::async_trait;
    use chrono::{DateTime, Duration};
    use std::sync::Mutex;

    /// Mock repository for testing
    struct MockBruteForceRepository {
        attempts: Mutex<Vec<FailedLoginAttempt>>,
        locked_at: Mutex<Option<DateTime<Utc>>>,
    }

    impl MockBruteForceRepository {
        fn new() -> Self {
            Self {
                attempts: Mutex::new(Vec::new()),
                locked_at: Mutex::new(None),
            }
        }
    }

    #[async_trait]
    impl BruteForceProtectionRepository for MockBruteForceRepository {
        async fn record_failed_attempt(
            &self,
            email: &str,
            ip_address: Option<&str>,
        ) -> Result<FailedLoginAttempt, Error> {
            let mut attempts = self.attempts.lock().unwrap();
            let attempt = FailedLoginAttempt {
                id: attempts.len() as i64 + 1,
                email: email.to_string(),
                ip_address: ip_address.map(|s| s.to_string()),
                attempted_at: Utc::now(),
            };
            attempts.push(attempt.clone());
            Ok(attempt)
        }

        async fn get_attempt_stats(
            &self,
            email: &str,
            since: DateTime<Utc>,
        ) -> Result<AttemptStats, Error> {
            let attempts = self.attempts.lock().unwrap();
            let matching: Vec<_> = attempts
                .iter()
                .filter(|a| a.email == email && a.attempted_at >= since)
                .collect();

            Ok(AttemptStats {
                count: matching.len() as u32,
                latest_at: matching.iter().map(|a| a.attempted_at).max(),
            })
        }

        async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
            let mut attempts = self.attempts.lock().unwrap();
            let before_len = attempts.len();
            attempts.retain(|a| a.email != email);
            Ok((before_len - attempts.len()) as u64)
        }

        async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error> {
            let locked_at = self.locked_at.lock().unwrap();
            if locked_at.is_some() {
                // Don't cleanup if account is locked
                return Ok(0);
            }
            drop(locked_at);

            let mut attempts = self.attempts.lock().unwrap();
            let before_len = attempts.len();
            attempts.retain(|a| a.attempted_at >= before);
            Ok((before_len - attempts.len()) as u64)
        }

        async fn set_locked_at(
            &self,
            _email: &str,
            locked_at: Option<DateTime<Utc>>,
        ) -> Result<(), Error> {
            *self.locked_at.lock().unwrap() = locked_at;
            Ok(())
        }

        async fn get_locked_at(&self, _email: &str) -> Result<Option<DateTime<Utc>>, Error> {
            Ok(*self.locked_at.lock().unwrap())
        }
    }

    #[tokio::test]
    async fn test_disabled_protection_returns_unlocked() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig::disabled();
        let service = BruteForceProtectionService::new(repo, config);

        let status = service
            .get_lockout_status("test@example.com")
            .await
            .unwrap();
        assert!(!status.is_locked);
        assert_eq!(status.failed_attempts, 0);
    }

    #[tokio::test]
    async fn test_disabled_protection_does_not_record() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig::disabled();
        let service = BruteForceProtectionService::new(repo.clone(), config);

        let status = service
            .record_failed_attempt("test@example.com", Some("127.0.0.1"))
            .await
            .unwrap();

        assert!(!status.is_locked);
        assert_eq!(status.failed_attempts, 0);
        assert_eq!(repo.attempts.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_single_attempt_not_locked() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig::default();
        let service = BruteForceProtectionService::new(repo, config);

        let status = service
            .record_failed_attempt("test@example.com", Some("127.0.0.1"))
            .await
            .unwrap();

        assert!(!status.is_locked);
        assert_eq!(status.failed_attempts, 1);
    }

    #[tokio::test]
    async fn test_lockout_after_max_attempts() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig {
            enabled: true,
            max_failed_attempts: 3,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        };
        let service = BruteForceProtectionService::new(repo, config);

        // Record 2 attempts - should not be locked
        for _ in 0..2 {
            let status = service
                .record_failed_attempt("test@example.com", None)
                .await
                .unwrap();
            assert!(!status.is_locked);
        }

        // 3rd attempt should trigger lockout
        let status = service
            .record_failed_attempt("test@example.com", None)
            .await
            .unwrap();
        assert!(status.is_locked);
        assert_eq!(status.failed_attempts, 3);
        assert!(status.locked_until.is_some());
    }

    #[tokio::test]
    async fn test_reset_attempts_clears_lockout() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig {
            enabled: true,
            max_failed_attempts: 2,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        };
        let service = BruteForceProtectionService::new(repo, config);

        // Lock the account
        for _ in 0..2 {
            service
                .record_failed_attempt("test@example.com", None)
                .await
                .unwrap();
        }
        assert!(service.is_locked("test@example.com").await.unwrap());

        // Reset attempts
        service.reset_attempts("test@example.com").await.unwrap();

        // Should be unlocked now
        assert!(!service.is_locked("test@example.com").await.unwrap());
        let status = service
            .get_lockout_status("test@example.com")
            .await
            .unwrap();
        assert_eq!(status.failed_attempts, 0);
    }

    #[tokio::test]
    async fn test_unlock_account_returns_was_locked() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig {
            enabled: true,
            max_failed_attempts: 2,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        };
        let service = BruteForceProtectionService::new(repo, config);

        // Lock the account
        for _ in 0..2 {
            service
                .record_failed_attempt("test@example.com", None)
                .await
                .unwrap();
        }

        // Unlock should return true (was locked)
        let was_locked = service.unlock_account("test@example.com").await.unwrap();
        assert!(was_locked);

        // Unlock again should return false (was not locked)
        let was_locked = service.unlock_account("test@example.com").await.unwrap();
        assert!(!was_locked);
    }

    #[tokio::test]
    async fn test_retry_after_seconds() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig {
            enabled: true,
            max_failed_attempts: 1,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        };
        let service = BruteForceProtectionService::new(repo, config);

        let status = service
            .record_failed_attempt("test@example.com", None)
            .await
            .unwrap();

        assert!(status.is_locked);
        let retry_after = status.retry_after_seconds().unwrap();
        // Should be roughly 15 minutes (900 seconds), allow some tolerance
        assert!(retry_after > 890 && retry_after <= 900);
    }

    #[tokio::test]
    async fn test_different_emails_tracked_separately() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig {
            enabled: true,
            max_failed_attempts: 2,
            lockout_period: Duration::minutes(15),
            retention_period: Duration::days(7),
        };
        let service = BruteForceProtectionService::new(repo, config);

        // Lock first account
        for _ in 0..2 {
            service
                .record_failed_attempt("user1@example.com", None)
                .await
                .unwrap();
        }

        // Second account should not be affected
        let status = service
            .get_lockout_status("user2@example.com")
            .await
            .unwrap();
        assert!(!status.is_locked);
        assert_eq!(status.failed_attempts, 0);

        // First account should be locked
        assert!(service.is_locked("user1@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn test_ip_address_recorded() {
        let repo = Arc::new(MockBruteForceRepository::new());
        let config = BruteForceProtectionConfig::default();
        let service = BruteForceProtectionService::new(repo.clone(), config);

        service
            .record_failed_attempt("test@example.com", Some("192.168.1.100"))
            .await
            .unwrap();

        let attempts = repo.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].ip_address.as_deref(), Some("192.168.1.100"));
    }

    #[tokio::test]
    async fn test_is_enabled() {
        let repo = Arc::new(MockBruteForceRepository::new());

        let enabled_service =
            BruteForceProtectionService::new(repo.clone(), BruteForceProtectionConfig::default());
        assert!(enabled_service.is_enabled());

        let disabled_service =
            BruteForceProtectionService::new(repo, BruteForceProtectionConfig::disabled());
        assert!(!disabled_service.is_enabled());
    }
}
