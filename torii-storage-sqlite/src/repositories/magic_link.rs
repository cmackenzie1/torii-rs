use async_trait::async_trait;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;
use torii_core::{
    Error, UserId, error::StorageError, repositories::MagicLinkRepository, storage::MagicToken,
};
use uuid::Uuid;

pub struct SqliteMagicLinkRepository {
    pool: SqlitePool,
}

impl SqliteMagicLinkRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MagicLinkRepository for SqliteMagicLinkRepository {
    async fn create_token(
        &self,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<MagicToken, Error> {
        let now = Utc::now();

        // Generate a random token
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + expires_in;

        // Insert the magic token
        sqlx::query(
            r#"
            INSERT INTO magic_links (user_id, token, used_at, expires_at, created_at, updated_at)
            VALUES (?1, ?2, NULL, ?3, ?4, ?5)
            "#,
        )
        .bind(user_id.to_string()) // user id
        .bind(&token)
        .bind(expires_at.timestamp())
        .bind(now.timestamp())
        .bind(now.timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(MagicToken::new(
            user_id.clone(),
            token,
            None,
            expires_at,
            now,
            now,
        ))
    }

    async fn verify_token(&self, token: &str) -> Result<Option<MagicToken>, Error> {
        let now = Utc::now();

        // Get the token and check if it's valid
        let result = sqlx::query_as::<_, (String, String, Option<i64>, i64, i64, i64)>(
            r#"
            SELECT user_id, token, used_at, expires_at, created_at, updated_at
            FROM magic_links
            WHERE token = ?1 AND used_at IS NULL AND expires_at > ?2
            "#,
        )
        .bind(token)
        .bind(now.timestamp())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        if let Some(row) = result {
            // Mark the token as used
            sqlx::query(
                r#"
                UPDATE magic_links
                SET used_at = ?1, updated_at = ?2
                WHERE token = ?3
                "#,
            )
            .bind(now.timestamp())
            .bind(now.timestamp())
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

            Ok(Some(MagicToken::new(
                UserId::from(row.0), // user_id
                row.1,               // token
                Some(now),
                chrono::DateTime::from_timestamp(row.3, 0).unwrap_or(now), // expires_at
                chrono::DateTime::from_timestamp(row.4, 0).unwrap_or(now), // created_at
                now,
            )))
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        let now = Utc::now();

        sqlx::query(
            r#"
            DELETE FROM magic_links
            WHERE expires_at <= ?1 OR used_at IS NOT NULL
            "#,
        )
        .bind(now.timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }
}
