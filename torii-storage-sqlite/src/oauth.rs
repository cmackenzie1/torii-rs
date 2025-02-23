use crate::{SqliteStorage, SqliteUser};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::storage::OAuthStorage;
use torii_core::{OAuthAccount, User, UserId};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteOAuthAccount {
    user_id: String,
    provider: String,
    subject: String,
    created_at: i64,
    updated_at: i64,
}

impl From<SqliteOAuthAccount> for OAuthAccount {
    fn from(oauth_account: SqliteOAuthAccount) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&oauth_account.user_id))
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(
                DateTime::from_timestamp(oauth_account.created_at, 0).expect("Invalid timestamp"),
            )
            .updated_at(
                DateTime::from_timestamp(oauth_account.updated_at, 0).expect("Invalid timestamp"),
            )
            .build()
            .unwrap()
    }
}

impl From<OAuthAccount> for SqliteOAuthAccount {
    fn from(oauth_account: OAuthAccount) -> Self {
        SqliteOAuthAccount {
            user_id: oauth_account.user_id.into_inner(),
            provider: oauth_account.provider,
            subject: oauth_account.subject,
            created_at: oauth_account.created_at.timestamp(),
            updated_at: oauth_account.updated_at.timestamp(),
        }
    }
}

#[async_trait]
impl OAuthStorage for SqliteStorage {
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Self::Error> {
        let now = Utc::now();
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING user_id, provider, subject, created_at, updated_at
            "#,
        )
        .bind(user_id.as_ref())
        .bind(provider)
        .bind(subject)
        .bind(now.timestamp())
        .bind(now.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create oauth account");
            Self::Error::Storage("Failed to create oauth account".to_string())
        })?;

        Ok(oauth_account.into())
    }

    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, SqliteUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at
            FROM users
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by provider and subject");
            Self::Error::Storage("Failed to get user by provider and subject".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Self::Error> {
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            SELECT user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oauth account");
            Self::Error::Storage("Failed to get oauth account".to_string())
        })?;

        if let Some(oauth_account) = oauth_account {
            Ok(Some(oauth_account.into()))
        } else {
            Ok(None)
        }
    }

    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Self::Error> {
        let now = Utc::now();
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user_id.as_ref())
            .bind(provider)
            .bind(subject)
            .bind(now.timestamp())
            .bind(now.timestamp())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to link oauth account");
                Self::Error::Storage("Failed to link oauth account".to_string())
            })?;

        Ok(())
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Self::Error> {
        sqlx::query("INSERT INTO nonces (id, value, expires_at) VALUES (?, ?, ?)")
            .bind(csrf_state)
            .bind(pkce_verifier)
            .bind((Utc::now() + expires_in).timestamp())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to save pkce verifier");
                Self::Error::Storage("Failed to save pkce verifier".to_string())
            })?;

        Ok(())
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Self::Error> {
        let pkce_verifier: Option<String> =
            sqlx::query_scalar("SELECT value FROM nonces WHERE id = ?")
                .bind(csrf_state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get pkce verifier");
                    Self::Error::Storage("Failed to get pkce verifier".to_string())
                })?;

        Ok(pkce_verifier)
    }
}
