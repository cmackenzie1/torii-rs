use crate::{SqliteStorage, SqliteUser};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use torii_core::error::StorageError;
use torii_core::storage::OAuthStorage;
use torii_core::{OAuthAccount, User, UserId};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteOAuthAccount {
    #[allow(dead_code)]
    id: Option<i64>,
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
            id: None,
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
    ) -> Result<OAuthAccount, torii_core::Error> {
        let now = Utc::now();
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING id, user_id, provider, subject, created_at, updated_at
            "#,
        )
        .bind(user_id.as_str())
        .bind(provider)
        .bind(subject)
        .bind(now.timestamp())
        .bind(now.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create oauth account");
            StorageError::Database("Failed to create oauth account".to_string())
        })?;

        Ok(oauth_account.into())
    }

    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, torii_core::Error> {
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
            StorageError::Database("Failed to get user by provider and subject".to_string())
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
    ) -> Result<Option<OAuthAccount>, torii_core::Error> {
        let oauth_account = sqlx::query_as::<_, SqliteOAuthAccount>(
            r#"
            SELECT id, user_id, provider, subject, created_at, updated_at
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
            StorageError::Database("Failed to get oauth account".to_string())
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
    ) -> Result<(), torii_core::Error> {
        let now = Utc::now();
        sqlx::query("INSERT INTO oauth_accounts (user_id, provider, subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
            .bind(user_id.as_str())
            .bind(provider)
            .bind(subject)
            .bind(now.timestamp())
            .bind(now.timestamp())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to link oauth account");
                StorageError::Database("Failed to link oauth account".to_string())
            })?;

        Ok(())
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), torii_core::Error> {
        sqlx::query(
            "INSERT INTO oauth_state (csrf_state, pkce_verifier, expires_at) VALUES (?, ?, ?)",
        )
        .bind(csrf_state)
        .bind(pkce_verifier)
        .bind((Utc::now() + expires_in).timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to save pkce verifier");
            StorageError::Database("Failed to save pkce verifier".to_string())
        })?;

        Ok(())
    }

    async fn get_pkce_verifier(
        &self,
        csrf_state: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let pkce_verifier: Option<String> =
            sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state WHERE csrf_state = ?")
                .bind(csrf_state)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "Failed to get pkce verifier");
                    StorageError::Database("Failed to get pkce verifier".to_string())
                })?;

        Ok(pkce_verifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::tests::setup_sqlite_storage;

    use crate::tests::create_test_user;

    #[tokio::test]
    async fn test_oauth_account_linking() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Link OAuth account
        storage
            .link_oauth_account(&user.id, "google", "oauth_id_123")
            .await
            .expect("Failed to link oauth account");

        // Try linking same account again - should fail
        let result = storage
            .link_oauth_account(&user.id, "google", "oauth_id_123")
            .await;
        assert!(result.is_err());

        // Get OAuth account
        let oauth_account = storage
            .get_oauth_account_by_provider_and_subject("google", "oauth_id_123")
            .await
            .expect("Failed to get oauth account");

        assert!(oauth_account.is_some());
        assert_eq!(oauth_account.unwrap().user_id, user.id);
    }

    #[tokio::test]
    async fn test_pkce_verifier() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        let csrf_state = "test_state";
        let pkce_verifier = "test_verifier";
        let expires_in = chrono::Duration::seconds(3600);

        // Store PKCE verifier
        storage
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
            .expect("Failed to store pkce verifier");

        // Get PKCE verifier
        let stored_verifier = storage
            .get_pkce_verifier(csrf_state)
            .await
            .expect("Failed to get pkce verifier");

        assert_eq!(stored_verifier, Some(pkce_verifier.to_string()));

        // Get non-existent PKCE verifier
        let non_existent = storage
            .get_pkce_verifier("non_existent")
            .await
            .expect("Failed to get pkce verifier");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_multiple_oauth_providers() {
        let storage = setup_sqlite_storage()
            .await
            .expect("Failed to setup storage");

        // Create test user
        let user = create_test_user(&storage, "1")
            .await
            .expect("Failed to create user");

        // Link multiple OAuth accounts
        storage
            .link_oauth_account(&user.id, "google", "google_id_123")
            .await
            .expect("Failed to link Google account");

        storage
            .link_oauth_account(&user.id, "github", "github_id_123")
            .await
            .expect("Failed to link GitHub account");

        // Verify both accounts are linked
        let google_user = storage
            .get_oauth_account_by_provider_and_subject("google", "google_id_123")
            .await
            .expect("Failed to get Google oauth account");

        let github_user = storage
            .get_oauth_account_by_provider_and_subject("github", "github_id_123")
            .await
            .expect("Failed to get GitHub oauth account");

        assert!(google_user.is_some());
        assert!(github_user.is_some());
        assert_eq!(google_user.unwrap().user_id, user.id);
        assert_eq!(github_user.unwrap().user_id, user.id);
    }
}
