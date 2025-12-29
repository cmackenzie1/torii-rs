//! PostgreSQL OAuth types
//!
//! This module contains the PostgreSQL-specific types for OAuth storage.

use chrono::{DateTime, Utc};
use std::time::Duration;
use torii_core::error::ValidationError;
use torii_core::{OAuthAccount, UserId};

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
