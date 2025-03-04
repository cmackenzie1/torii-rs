use async_trait::async_trait;
use chrono::DateTime;
use torii_core::{
    UserId,
    error::StorageError,
    storage::{MagicLinkStorage, MagicToken},
};

use crate::SqliteStorage;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteMagicToken {
    pub id: Option<String>,
    pub user_id: String,
    pub token: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
}

impl From<SqliteMagicToken> for MagicToken {
    fn from(row: SqliteMagicToken) -> Self {
        MagicToken::new(
            UserId::new(&row.user_id),
            row.token.clone(),
            DateTime::from_timestamp(row.expires_at, 0).unwrap(),
            DateTime::from_timestamp(row.created_at, 0).unwrap(),
            DateTime::from_timestamp(row.updated_at, 0).unwrap(),
        )
    }
}

impl From<&MagicToken> for SqliteMagicToken {
    fn from(token: &MagicToken) -> Self {
        SqliteMagicToken {
            id: None,
            user_id: token.user_id.as_str().to_string(),
            token: token.token.clone(),
            expires_at: token.expires_at.timestamp(),
            created_at: token.created_at.timestamp(),
            updated_at: token.updated_at.timestamp(),
        }
    }
}

#[async_trait]
impl MagicLinkStorage for SqliteStorage {
    async fn save_magic_token(&self, token: &MagicToken) -> Result<(), StorageError> {
        let row = SqliteMagicToken::from(token);

        sqlx::query("INSERT INTO magic_links (user_id, token, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(row.user_id)
            .bind(row.token)
            .bind(row.expires_at)
            .bind(row.created_at)
            .bind(row.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    async fn get_magic_token(&self, token: &str) -> Result<Option<MagicToken>, StorageError> {
        let row: Option<SqliteMagicToken> =
            sqlx::query_as("SELECT id, user_id, token, expires_at, created_at, updated_at FROM magic_links WHERE token = ?")
                .bind(token)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|row| row.into()))
    }
}
