//! SQLite implementation of the brute force protection repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use torii_core::{
    Error,
    error::StorageError,
    repositories::BruteForceProtectionRepository,
    storage::{AttemptStats, FailedLoginAttempt},
};

/// SQLite repository for brute force protection data.
pub struct SqliteBruteForceRepository {
    pool: SqlitePool,
}

impl SqliteBruteForceRepository {
    /// Create a new SQLite brute force repository.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

/// Internal struct for query results
#[derive(Debug, sqlx::FromRow)]
struct SqliteFailedLoginAttempt {
    id: i64,
    email: String,
    ip_address: Option<String>,
    attempted_at: i64,
}

impl From<SqliteFailedLoginAttempt> for FailedLoginAttempt {
    fn from(row: SqliteFailedLoginAttempt) -> Self {
        FailedLoginAttempt {
            id: row.id,
            email: row.email,
            ip_address: row.ip_address,
            attempted_at: DateTime::from_timestamp(row.attempted_at, 0).expect("Invalid timestamp"),
        }
    }
}

/// Internal struct for attempt stats query
#[derive(Debug, sqlx::FromRow)]
struct SqliteAttemptStats {
    count: i32,
    latest_at: Option<i64>,
}

#[async_trait]
impl BruteForceProtectionRepository for SqliteBruteForceRepository {
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        let now = Utc::now().timestamp();

        let row = sqlx::query_as::<_, SqliteFailedLoginAttempt>(
            r#"
            INSERT INTO failed_login_attempts (email, ip_address, attempted_at)
            VALUES (?, ?, ?)
            RETURNING id, email, ip_address, attempted_at
            "#,
        )
        .bind(email)
        .bind(ip_address)
        .bind(now)
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
        let since_timestamp = since.timestamp();

        let row = sqlx::query_as::<_, SqliteAttemptStats>(
            r#"
            SELECT 
                COUNT(*) as count,
                MAX(attempted_at) as latest_at
            FROM failed_login_attempts
            WHERE email = ? AND attempted_at >= ?
            "#,
        )
        .bind(email)
        .bind(since_timestamp)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get attempt stats");
            StorageError::Database("Failed to get attempt stats".to_string())
        })?;

        Ok(AttemptStats {
            count: row.count as u32,
            latest_at: row.latest_at.and_then(|ts| DateTime::from_timestamp(ts, 0)),
        })
    }

    async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
        let result = sqlx::query("DELETE FROM failed_login_attempts WHERE email = ?")
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
        let before_timestamp = before.timestamp();

        // Only delete attempts for users who are not locked
        // This prevents accidentally unlocking accounts during cleanup
        let result = sqlx::query(
            r#"
            DELETE FROM failed_login_attempts
            WHERE attempted_at < ?
            AND email NOT IN (
                SELECT email FROM users WHERE locked_at IS NOT NULL
            )
            "#,
        )
        .bind(before_timestamp)
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
        let locked_at_timestamp = locked_at.map(|dt| dt.timestamp());

        // Update if user exists, ignore if not (prevents enumeration)
        sqlx::query("UPDATE users SET locked_at = ? WHERE email = ?")
            .bind(locked_at_timestamp)
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
        let row: Option<(Option<i64>,)> =
            sqlx::query_as("SELECT locked_at FROM users WHERE email = ?")
                .bind(email)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get locked_at");
                    StorageError::Database("Failed to get locked_at".to_string())
                })?;

        Ok(row
            .and_then(|(locked_at,)| locked_at)
            .and_then(|ts| DateTime::from_timestamp(ts, 0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::{
        AddLockedAtToUsers, CreateFailedLoginAttemptsTable, CreateIndexes,
        CreateOAuthAccountsTable, CreatePasskeyChallengesTable, CreatePasskeysTable,
        CreateSessionsTable, CreateUsersTable, SqliteMigrationManager,
    };
    use chrono::Duration;
    use sqlx::SqlitePool;
    use torii_migration::{Migration, MigrationManager};

    async fn setup_test_db() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");

        let manager = SqliteMigrationManager::new(pool.clone());
        manager
            .initialize()
            .await
            .expect("Failed to initialize migrations");

        let migrations: Vec<Box<dyn Migration<sqlx::Sqlite>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
            Box::new(CreateIndexes),
            Box::new(CreateFailedLoginAttemptsTable),
            Box::new(AddLockedAtToUsers),
        ];
        manager
            .up(&migrations)
            .await
            .expect("Failed to run migrations");

        pool
    }

    async fn create_test_user(pool: &SqlitePool, email: &str) {
        sqlx::query("INSERT INTO users (id, email, created_at, updated_at) VALUES (?, ?, ?, ?)")
            .bind(format!("usr_{email}"))
            .bind(email)
            .bind(Utc::now().timestamp())
            .bind(Utc::now().timestamp())
            .execute(pool)
            .await
            .expect("Failed to create test user");
    }

    #[tokio::test]
    async fn test_record_failed_attempt() {
        let pool = setup_test_db().await;
        let repo = SqliteBruteForceRepository::new(pool);

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
        let pool = setup_test_db().await;
        let repo = SqliteBruteForceRepository::new(pool);

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
        let pool = setup_test_db().await;
        let repo = SqliteBruteForceRepository::new(pool);

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
        let pool = setup_test_db().await;
        let repo = SqliteBruteForceRepository::new(pool);

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
        let pool = setup_test_db().await;
        create_test_user(&pool, "test@example.com").await;
        let repo = SqliteBruteForceRepository::new(pool);

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
        let pool = setup_test_db().await;
        let repo = SqliteBruteForceRepository::new(pool);

        // Should not error for non-existent user
        let result = repo
            .set_locked_at("nonexistent@example.com", Some(Utc::now()))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_respects_locked_users() {
        let pool = setup_test_db().await;
        create_test_user(&pool, "locked@example.com").await;
        create_test_user(&pool, "unlocked@example.com").await;
        let repo = SqliteBruteForceRepository::new(pool);

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
