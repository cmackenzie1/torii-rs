use crate::{PostgresStorage, PostgresUser};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::time::Duration;
use torii_core::error::{StorageError, ValidationError};
use torii_core::storage::OAuthStorage;
use torii_core::{OAuthAccount, User, UserId};

#[derive(Default)]
pub struct PostgresOAuthAccountBuilder {
    user_id: Option<UserId>,
    provider: Option<String>,
    subject: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl PostgresOAuthAccountBuilder {
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

    pub fn build(self) -> Result<PostgresOAuthAccount, torii_core::Error> {
        let now = Utc::now();
        Ok(PostgresOAuthAccount {
            id: None,
            user_id: self
                .user_id
                .ok_or(ValidationError::MissingField(
                    "User ID is required".to_string(),
                ))?
                .to_string(),
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

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresOAuthAccount {
    pub id: Option<i64>,
    pub user_id: String,
    pub provider: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl PostgresOAuthAccount {
    pub fn builder() -> PostgresOAuthAccountBuilder {
        PostgresOAuthAccountBuilder::default()
    }

    pub fn new(user_id: UserId, provider: impl Into<String>, subject: impl Into<String>) -> Self {
        PostgresOAuthAccountBuilder::default()
            .user_id(user_id)
            .provider(provider.into())
            .subject(subject.into())
            .build()
            .expect("Default builder should never fail")
    }

    pub fn is_expired(&self, ttl: Duration) -> bool {
        Utc::now() > self.created_at + ttl
    }
}

impl From<PostgresOAuthAccount> for OAuthAccount {
    fn from(oauth_account: PostgresOAuthAccount) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&oauth_account.user_id))
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(oauth_account.created_at)
            .updated_at(oauth_account.updated_at)
            .build()
            .expect("Default builder should never fail")
    }
}

impl From<OAuthAccount> for PostgresOAuthAccount {
    fn from(oauth_account: OAuthAccount) -> Self {
        PostgresOAuthAccount::builder()
            .user_id(oauth_account.user_id)
            .provider(oauth_account.provider)
            .subject(oauth_account.subject)
            .created_at(oauth_account.created_at)
            .updated_at(oauth_account.updated_at)
            .build()
            .expect("Default builder should never fail")
    }
}

#[async_trait]
impl OAuthStorage for PostgresStorage {
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, torii_core::Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(user_id.as_str())
            .bind(provider)
            .bind(subject)
            .bind(Utc::now())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to create oauth account");
                StorageError::Database("Failed to create oauth account".to_string())
            })?;

        let oauth_account = sqlx::query_as::<_, PostgresOAuthAccount>(
            r#"
            SELECT id, user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get oauth account");
            StorageError::Database("Failed to get oauth account".to_string())
        })?;

        Ok(oauth_account.into())
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            "INSERT INTO oauth_state (csrf_state, pkce_verifier, expires_at) VALUES ($1, $2, $3) RETURNING value",
        )
        .bind(csrf_state)
        .bind(pkce_verifier)
        .bind(Utc::now() + expires_in)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to store pkce verifier");
            StorageError::Database("Failed to store pkce verifier".to_string())
        })?;

        Ok(())
    }

    async fn get_pkce_verifier(
        &self,
        csrf_state: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let pkce_verifier =
            sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state WHERE csrf_state = $1")
                .bind(csrf_state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get pkce verifier");
                    StorageError::Database("Failed to get pkce verifier".to_string())
                })?;

        Ok(pkce_verifier)
    }

    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, torii_core::Error> {
        let oauth_account = sqlx::query_as::<_, PostgresOAuthAccount>(
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
            tracing::error!(error = %e, "Failed to get oauth account");
            StorageError::Database("Failed to get oauth account".to_string())
        })?;

        if let Some(oauth_account) = oauth_account {
            Ok(Some(oauth_account.into()))
        } else {
            Ok(None)
        }
    }

    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, torii_core::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at
            FROM users
            WHERE provider = $1 AND subject = $2
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by provider and subject");
            StorageError::Database("Failed to get user by provider and subject".to_string())
        })?;

        if let Some(user) = user {
            Ok(Some(user.into()))
        } else {
            Ok(None)
        }
    }

    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), torii_core::Error> {
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)")
            .bind(user_id.as_str())
            .bind(provider)
            .bind(subject)
            .bind(Utc::now())
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to link oauth account");
                StorageError::Database("Failed to link oauth account".to_string())
            })?;

        Ok(())
    }
}
