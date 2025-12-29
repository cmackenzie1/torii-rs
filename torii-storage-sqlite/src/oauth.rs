//! SQLite OAuth types
//!
//! This module contains the SQLite-specific types for OAuth storage.
//! The actual OAuth repository implementation is in the repositories module.

use chrono::DateTime;
use torii_core::{OAuthAccount, UserId};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SqliteOAuthAccount {
    #[allow(dead_code)]
    pub id: Option<i64>,
    pub user_id: String,
    pub provider: String,
    pub subject: String,
    pub created_at: i64,
    pub updated_at: i64,
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

#[cfg(test)]
mod tests {
    use crate::SqliteStorage;
    use crate::tests::{create_test_user, setup_sqlite_storage};
    use chrono::Utc;
    use torii_core::error::StorageError;

    // Helper to link OAuth account for testing
    async fn link_oauth_account(
        storage: &SqliteStorage,
        user_id: &torii_core::UserId,
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
            .execute(&storage.pool)
            .await
            .map_err(|e| {
                torii_core::Error::Storage(StorageError::Database(e.to_string()))
            })?;
        Ok(())
    }

    // Helper to get OAuth account for testing
    async fn get_oauth_account(
        storage: &SqliteStorage,
        provider: &str,
        subject: &str,
    ) -> Result<Option<super::SqliteOAuthAccount>, torii_core::Error> {
        let oauth_account = sqlx::query_as::<_, super::SqliteOAuthAccount>(
            r#"
            SELECT id, user_id, provider, subject, created_at, updated_at
            FROM oauth_accounts
            WHERE provider = ? AND subject = ?
            "#,
        )
        .bind(provider)
        .bind(subject)
        .fetch_optional(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(oauth_account)
    }

    // Helper to store PKCE verifier for testing
    async fn store_pkce_verifier(
        storage: &SqliteStorage,
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
        .execute(&storage.pool)
        .await
        .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(())
    }

    // Helper to get PKCE verifier for testing
    async fn get_pkce_verifier(
        storage: &SqliteStorage,
        csrf_state: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let pkce_verifier: Option<String> =
            sqlx::query_scalar("SELECT pkce_verifier FROM oauth_state WHERE csrf_state = ?")
                .bind(csrf_state)
                .fetch_optional(&storage.pool)
                .await
                .map_err(|e| torii_core::Error::Storage(StorageError::Database(e.to_string())))?;
        Ok(pkce_verifier)
    }

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
        link_oauth_account(&storage, &user.id, "google", "oauth_id_123")
            .await
            .expect("Failed to link oauth account");

        // Try linking same account again - should fail
        let result = link_oauth_account(&storage, &user.id, "google", "oauth_id_123").await;
        assert!(result.is_err());

        // Get OAuth account
        let oauth_account = get_oauth_account(&storage, "google", "oauth_id_123")
            .await
            .expect("Failed to get oauth account");

        assert!(oauth_account.is_some());
        assert_eq!(oauth_account.unwrap().user_id, user.id.as_str());
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
        store_pkce_verifier(&storage, csrf_state, pkce_verifier, expires_in)
            .await
            .expect("Failed to store pkce verifier");

        // Get PKCE verifier
        let stored_verifier = get_pkce_verifier(&storage, csrf_state)
            .await
            .expect("Failed to get pkce verifier");

        assert_eq!(stored_verifier, Some(pkce_verifier.to_string()));

        // Get non-existent PKCE verifier
        let non_existent = get_pkce_verifier(&storage, "non_existent")
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
        link_oauth_account(&storage, &user.id, "google", "google_id_123")
            .await
            .expect("Failed to link Google account");

        link_oauth_account(&storage, &user.id, "github", "github_id_123")
            .await
            .expect("Failed to link GitHub account");

        // Verify both accounts are linked
        let google_account = get_oauth_account(&storage, "google", "google_id_123")
            .await
            .expect("Failed to get Google oauth account");

        let github_account = get_oauth_account(&storage, "github", "github_id_123")
            .await
            .expect("Failed to get GitHub oauth account");

        assert!(google_account.is_some());
        assert!(github_account.is_some());
        assert_eq!(google_account.unwrap().user_id, user.id.as_str());
        assert_eq!(github_account.unwrap().user_id, user.id.as_str());
    }
}
