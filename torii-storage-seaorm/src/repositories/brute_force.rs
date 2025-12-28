//! SeaORM implementation of the brute force protection repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect,
};
use torii_core::{
    Error,
    error::StorageError,
    repositories::BruteForceProtectionRepository,
    storage::{AttemptStats, FailedLoginAttempt},
};

use crate::entities::{failed_login_attempt, user};

/// SeaORM repository for brute force protection data.
pub struct SeaORMBruteForceRepository {
    db: DatabaseConnection,
}

impl SeaORMBruteForceRepository {
    /// Create a new SeaORM brute force repository.
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl BruteForceProtectionRepository for SeaORMBruteForceRepository {
    async fn record_failed_attempt(
        &self,
        email: &str,
        ip_address: Option<&str>,
    ) -> Result<FailedLoginAttempt, Error> {
        let now = Utc::now();

        let model = failed_login_attempt::ActiveModel {
            email: Set(email.to_string()),
            ip_address: Set(ip_address.map(|s| s.to_string())),
            attempted_at: Set(now),
            ..Default::default()
        };

        let result = model.insert(&self.db).await.map_err(|e| {
            StorageError::Database(format!("Failed to record failed login attempt: {e}"))
        })?;

        Ok(FailedLoginAttempt {
            id: result.id,
            email: result.email,
            ip_address: result.ip_address,
            attempted_at: result.attempted_at,
        })
    }

    async fn get_attempt_stats(
        &self,
        email: &str,
        since: DateTime<Utc>,
    ) -> Result<AttemptStats, Error> {
        use sea_orm::sea_query::Expr;

        // Query for count and max attempted_at
        let results = failed_login_attempt::Entity::find()
            .filter(failed_login_attempt::Column::Email.eq(email))
            .filter(failed_login_attempt::Column::AttemptedAt.gte(since))
            .select_only()
            .column_as(Expr::col(failed_login_attempt::Column::Id).count(), "count")
            .column_as(
                Expr::col(failed_login_attempt::Column::AttemptedAt).max(),
                "latest_at",
            )
            .into_tuple::<(i64, Option<DateTime<Utc>>)>()
            .one(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get attempt stats: {e}")))?;

        match results {
            Some((count, latest_at)) => Ok(AttemptStats {
                count: count as u32,
                latest_at,
            }),
            None => Ok(AttemptStats::default()),
        }
    }

    async fn clear_attempts(&self, email: &str) -> Result<u64, Error> {
        let result = failed_login_attempt::Entity::delete_many()
            .filter(failed_login_attempt::Column::Email.eq(email))
            .exec(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to clear attempts: {e}")))?;

        Ok(result.rows_affected)
    }

    async fn cleanup_old_attempts(&self, before: DateTime<Utc>) -> Result<u64, Error> {
        // Get emails of locked users
        let locked_emails: Vec<String> = user::Entity::find()
            .filter(user::Column::LockedAt.is_not_null())
            .select_only()
            .column(user::Column::Email)
            .into_tuple()
            .all(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get locked users: {e}")))?;

        // Delete old attempts for unlocked users
        let mut delete_query = failed_login_attempt::Entity::delete_many()
            .filter(failed_login_attempt::Column::AttemptedAt.lt(before));

        if !locked_emails.is_empty() {
            delete_query =
                delete_query.filter(failed_login_attempt::Column::Email.is_not_in(locked_emails));
        }

        let result = delete_query
            .exec(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to cleanup old attempts: {e}")))?;

        Ok(result.rows_affected)
    }

    async fn set_locked_at(
        &self,
        email: &str,
        locked_at: Option<DateTime<Utc>>,
    ) -> Result<(), Error> {
        // Find the user first
        let user_model = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to find user: {e}")))?;

        // If user doesn't exist, silently return (prevents enumeration)
        if let Some(user_model) = user_model {
            let mut active_model: user::ActiveModel = user_model.into();
            active_model.locked_at = Set(locked_at);
            active_model.updated_at = Set(Utc::now());
            active_model
                .update(&self.db)
                .await
                .map_err(|e| StorageError::Database(format!("Failed to set locked_at: {e}")))?;
        }

        Ok(())
    }

    async fn get_locked_at(&self, email: &str) -> Result<Option<DateTime<Utc>>, Error> {
        let user_model = user::Entity::find()
            .filter(user::Column::Email.eq(email))
            .one(&self.db)
            .await
            .map_err(|e| StorageError::Database(format!("Failed to get locked_at: {e}")))?;

        Ok(user_model.and_then(|u| u.locked_at))
    }
}
