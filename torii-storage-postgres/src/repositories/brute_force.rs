//! PostgreSQL implementation of the brute force protection repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use torii_core::{
    Error,
    error::StorageError,
    repositories::BruteForceProtectionRepository,
    storage::{AttemptStats, FailedLoginAttempt},
};

/// PostgreSQL repository for brute force protection data.
pub struct PostgresBruteForceRepository {
    pool: PgPool,
}

impl PostgresBruteForceRepository {
    /// Create a new PostgreSQL brute force repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Internal struct for query results
#[derive(Debug, sqlx::FromRow)]
struct PgFailedLoginAttempt {
    id: i64,
    email: String,
    ip_address: Option<String>,
    attempted_at: DateTime<Utc>,
}

impl From<PgFailedLoginAttempt> for FailedLoginAttempt {
    fn from(row: PgFailedLoginAttempt) -> Self {
        FailedLoginAttempt {
            id: row.id,
            email: row.email,
            ip_address: row.ip_address,
            attempted_at: row.attempted_at,
        }
    }
}

/// Internal struct for attempt stats query
#[derive(Debug, sqlx::FromRow)]
struct PgAttemptStats {
    count: i64,
    latest_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl BruteForceProtectionRepository for PostgresBruteForceRepository {
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        let row = sqlx::query_as::<_, PgFailedLoginAttempt>(
            r#"
            INSERT INTO failed_login_attempts (email, ip_address, attempted_at)
            VALUES ($1, $2, NOW())
            RETURNING id, email, ip_address, attempted_at
            "#,
        )
        .bind(email)
        .bind(ip_address)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to record failed login attempt");
            StorageError::Database("Failed to record failed login attempt".to_string())
        })?;

        Ok(row.into())
    }

    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        let row = sqlx::query_as::<_, PgAttemptStats>(
            r#"
            SELECT 
                COUNT(*) as count,
                MAX(attempted_at) as latest_at
            FROM failed_login_attempts
            WHERE email = $1 AND attempted_at >= $2
            "#,
        )
        .bind(email)
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get attempt stats");
            StorageError::Database("Failed to get attempt stats".to_string())
        })?;

        Ok(AttemptStats {
            count: row.count as u32,
            latest_at: row.latest_at,
        })
    }

    async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM failed_login_attempts WHERE email = $1")
            .bind(email)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to clear attempts");
                StorageError::Database("Failed to clear attempts".to_string())
            })?;

        Ok(result.rows_affected())
    }

    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        // Only delete attempts for users who are not locked
        // This prevents accidentally unlocking accounts during cleanup
        let result = sqlx::query(
            r#"
            DELETE FROM failed_login_attempts
            WHERE attempted_at < $1
            AND email NOT IN (
                SELECT email FROM users WHERE locked_at IS NOT NULL
            )
            "#,
        )
        .bind(before)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to cleanup old attempts");
            StorageError::Database("Failed to cleanup old attempts".to_string())
        })?;

        Ok(result.rows_affected())
    }

    async fn set_locked_at(
        &self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        // Update if user exists, ignore if not (prevents enumeration)
        sqlx::query("UPDATE users SET locked_at = $1 WHERE email = $2")
            .bind(locked_at)
            .bind(email)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to set locked_at");
                StorageError::Database("Failed to set locked_at".to_string())
            })?;

        Ok(())
    }

    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let row: Option<(Option<DateTime<Utc>>,)> =
            sqlx::query_as("SELECT locked_at FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get locked_at");
                    StorageError::Database("Failed to get locked_at".to_string())
                })?;

        Ok(row.and_then(|(locked_at,)| locked_at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::setup_test_db;
    use chrono::Duration;
    use torii_core::UserId;

    async fn create_test_user(storage: &crate::PostgresStorage, email: &str) {
        use crate::repositories::PostgresUserRepository;
        use torii_core::{repositories::UserRepository, storage::NewUser};
        let repo = PostgresUserRepository::new(storage.pool.clone());
        repo.create(
            NewUser::builder()
                .id(UserId::new_random())
                .email(email.to_string())
                .build()
                .expect("Failed to build user"),
        )
        .await
        .expect("Failed to create test user");
    }

    #[tokio::test]
    async fn test_record_failed_attempt() {
        let storage = setup_test_db().await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        let attempt = repo
            .record_failed_attempt("test@example.com", Some("192.168.1.1"))
            .await
            .expect("Failed to record attempt");

        assert_eq!(attempt.email, "test@example.com");
        assert_eq!(attempt.ip_address, Some("192.168.1.1".to_string()));
        assert!(attempt.id > 0);
    }

    #[tokio::test]
    async fn test_get_attempt_stats() {
        let storage = setup_test_db().await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Record multiple attempts
        for _ in 0..3 {
            repo.record_failed_attempt("test@example.com", None)
                .await
                .expect("Failed to record attempt");
        }

        let stats = repo
            .get_attempt_stats("test@example.com", Utc::now() - Duration::hours(1))
            .await
            .expect("Failed to get stats");

        assert_eq!(stats.count, 3);
        assert!(stats.latest_at.is_some());
    }

    #[tokio::test]
    async fn test_get_attempt_stats_respects_since() {
        let storage = setup_test_db().await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Record an attempt
        repo.record_failed_attempt("test@example.com", None)
            .await
            .expect("Failed to record attempt");

        // Query with future timestamp should return 0
        let stats = repo
            .get_attempt_stats("test@example.com", Utc::now() + Duration::hours(1))
            .await
            .expect("Failed to get stats");

        assert_eq!(stats.count, 0);
        assert!(stats.latest_at.is_none());
    }

    #[tokio::test]
    async fn test_clear_attempts() {
        let storage = setup_test_db().await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Record attempts for two emails
        for _ in 0..3 {
            repo.record_failed_attempt("test1@example.com", None)
                .await
                .unwrap();
            repo.record_failed_attempt("test2@example.com", None)
                .await
                .unwrap();
        }

        // Clear attempts for one email
        let cleared = repo.clear_attempts("test1@example.com").await.unwrap();
        assert_eq!(cleared, 3);

        // Verify test1 has no attempts
        let stats1 = repo
            .get_attempt_stats("test1@example.com", Utc::now() - Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(stats1.count, 0);

        // Verify test2 still has attempts
        let stats2 = repo
            .get_attempt_stats("test2@example.com", Utc::now() - Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(stats2.count, 3);
    }

    #[tokio::test]
    async fn test_set_and_get_locked_at() {
        let storage = setup_test_db().await;
        create_test_user(&storage, "test@example.com").await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Initially should be None
        let locked_at = repo.get_locked_at("test@example.com").await.unwrap();
        assert!(locked_at.is_none());

        // Set locked_at
        let now = Utc::now();
        repo.set_locked_at("test@example.com", Some(now))
            .await
            .unwrap();

        // Should now have a value
        let locked_at = repo.get_locked_at("test@example.com").await.unwrap();
        assert!(locked_at.is_some());

        // Clear locked_at
        repo.set_locked_at("test@example.com", None).await.unwrap();

        // Should be None again
        let locked_at = repo.get_locked_at("test@example.com").await.unwrap();
        assert!(locked_at.is_none());
    }

    #[tokio::test]
    async fn test_set_locked_at_nonexistent_user() {
        let storage = setup_test_db().await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Should not error for non-existent user
        let result = repo
            .set_locked_at("nonexistent@example.com", Some(Utc::now()))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_respects_locked_users() {
        let storage = setup_test_db().await;
        create_test_user(&storage, "locked@example.com").await;
        create_test_user(&storage, "unlocked@example.com").await;
        let repo = PostgresBruteForceRepository::new(storage.pool.clone());

        // Record old attempts for both users
        repo.record_failed_attempt("locked@example.com", None)
            .await
            .unwrap();
        repo.record_failed_attempt("unlocked@example.com", None)
            .await
            .unwrap();

        // Lock one user
        repo.set_locked_at("locked@example.com", Some(Utc::now()))
            .await
            .unwrap();

        // Cleanup with future timestamp (should delete all old records except for locked user)
        let deleted = repo
            .cleanup_old_attempts(Utc::now() + Duration::hours(1))
            .await
            .unwrap();

        // Should only delete unlocked user's attempts
        assert_eq!(deleted, 1);

        // Locked user should still have attempts
        let stats = repo
            .get_attempt_stats("locked@example.com", Utc::now() - Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(stats.count, 1);

        // Unlocked user should have no attempts
        let stats = repo
            .get_attempt_stats("unlocked@example.com", Utc::now() - Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(stats.count, 0);
    }
}
