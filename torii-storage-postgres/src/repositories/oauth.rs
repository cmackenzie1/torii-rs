//! PostgreSQL implementation of the OAuth repository.

use async_trait::async_trait;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use torii_core::{
    Error, OAuthAccount, User, UserId, error::StorageError, repositories::OAuthRepository,
};

use crate::PostgresUser;
use crate::oauth::PostgresOAuthAccount;

/// PostgreSQL repository for OAuth data.
pub struct PostgresOAuthRepository {
    pool: PgPool,
}

impl PostgresOAuthRepository {
    /// Create a new PostgreSQL OAuth repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OAuthRepository for PostgresOAuthRepository {
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        let now = Utc::now();
        let account = sqlx::query_as::<_, PostgresOAuthAccount>(
            r#"
            INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, user_id, provider, subject, created_at, updated_at
            "#,
        )
        .bind(user_id.as_str())
        .bind(provider)
        .bind(subject)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create OAuth account");
            Error::Storage(StorageError::Database(
                "Failed to create OAuth account".to_string(),
            ))
        })?;

        Ok(account.into())
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT u.id, u.email, u.name, u.email_verified_at, u.locked_at, u.created_at, u.updated_at
            FROM users u
            INNER JOIN oauth_accounts oa ON u.id = oa.user_id
            WHERE oa.provider = $1 AND oa.subject = $2
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find user by OAuth provider");
            Error::Storage(StorageError::Database(
                "Failed to find user by OAuth provider".to_string(),
            ))
        })?;

        Ok(user.map(|u| u.into()))
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        let account = sqlx::query_as::<_, PostgresOAuthAccount>(
            r#"
            SELECT id, user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE provider = $1 AND subject = $2
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find OAuth account by provider");
            Error::Storage(StorageError::Database(
                "Failed to find OAuth account by provider".to_string(),
            ))
        })?;

        Ok(account.map(|a| a.into()))
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        let now = Utc::now();
        sqlx::query(
            r#"
            INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (provider, subject) DO NOTHING
            "#,
        )
        .bind(user_id.as_str())
        .bind(provider)
        .bind(subject)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to link OAuth account");
            Error::Storage(StorageError::Database(
                "Failed to link OAuth account".to_string(),
            ))
        })?;

        Ok(())
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        let now = Utc::now();
        let expires_at = now + expires_in;
        sqlx::query(
            r#"
            INSERT INTO oauth_state (csrf_state, pkce_verifier, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (csrf_state) DO UPDATE SET pkce_verifier = $2, expires_at = $3, updated_at = $5
            "#,
        )
        .bind(csrf_state)
        .bind(pkce_verifier)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store PKCE verifier");
            Error::Storage(StorageError::Database(
                "Failed to store PKCE verifier".to_string(),
            ))
        })?;

        Ok(())
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        let now = Utc::now();
        let verifier: Option<String> = sqlx::query_scalar(
            r#"
            SELECT pkce_verifier FROM oauth_state
            WHERE csrf_state = $1 AND expires_at > $2
            "#,
        )
        .bind(csrf_state)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get PKCE verifier");
            Error::Storage(StorageError::Database(
                "Failed to get PKCE verifier".to_string(),
            ))
        })?;

        Ok(verifier)
    }

    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
        sqlx::query("DELETE FROM oauth_state WHERE csrf_state = $1")
            .bind(csrf_state)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete PKCE verifier");
                Error::Storage(StorageError::Database(
                    "Failed to delete PKCE verifier".to_string(),
                ))
            })?;

        Ok(())
    }
}
