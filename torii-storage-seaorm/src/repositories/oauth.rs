use crate::SeaORMStorage;
use async_trait::async_trait;
use chrono::Duration;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, OAuthAccount, User, UserId, repositories::OAuthRepository, storage::OAuthStorage,
};

pub struct SeaORMOAuthRepository {
    storage: SeaORMStorage,
}

impl SeaORMOAuthRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self {
            storage: SeaORMStorage::new(pool),
        }
    }
}

#[async_trait]
impl OAuthRepository for SeaORMOAuthRepository {
    async fn create_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Error> {
        self.storage
            .create_oauth_account(provider, subject, user_id)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        self.storage
            .get_user_by_provider_and_subject(provider, subject)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.storage
            .get_oauth_account_by_provider_and_subject(provider, subject)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        self.storage
            .link_oauth_account(user_id, provider, subject)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.storage
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        self.storage
            .get_pkce_verifier(csrf_state)
            .await
            .map_err(|e| Error::Storage(torii_core::error::StorageError::Database(e.to_string())))
    }

    async fn delete_pkce_verifier(&self, _csrf_state: &str) -> Result<(), Error> {
        // TODO: This method is not available in the storage trait yet
        // For now, this is a placeholder implementation
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;
    use torii_core::storage::{NewUser, UserStorage};

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    async fn create_test_user(pool: &DatabaseConnection) -> UserId {
        let storage = SeaORMStorage::new(pool.clone());
        let new_user = NewUser {
            id: UserId::new_random(),
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            email_verified_at: None,
        };

        let user = storage.create_user(&new_user).await.unwrap();
        user.id
    }

    #[tokio::test]
    async fn test_create_account() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let account = repo
            .create_account("google", "12345", &user_id)
            .await
            .unwrap();

        assert_eq!(account.provider, "google");
        assert_eq!(account.subject, "12345");
        assert_eq!(account.user_id, user_id);
    }

    #[tokio::test]
    async fn test_find_user_by_provider() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let _account = repo
            .create_account("google", "12345", &user_id)
            .await
            .unwrap();

        let found_user = repo.find_user_by_provider("google", "12345").await.unwrap();

        assert!(found_user.is_some());
        assert_eq!(found_user.unwrap().id, user_id);
    }

    #[tokio::test]
    async fn test_find_user_by_provider_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool);

        let result = repo
            .find_user_by_provider("google", "nonexistent")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_find_account_by_provider() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let _account = repo
            .create_account("github", "67890", &user_id)
            .await
            .unwrap();

        let found_account = repo
            .find_account_by_provider("github", "67890")
            .await
            .unwrap();

        assert!(found_account.is_some());
        let found_account = found_account.unwrap();
        assert_eq!(found_account.provider, "github");
        assert_eq!(found_account.subject, "67890");
        assert_eq!(found_account.user_id, user_id);
    }

    #[tokio::test]
    async fn test_find_account_by_provider_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool);

        let result = repo
            .find_account_by_provider("github", "nonexistent")
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_link_account() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool.clone());
        let user_id = create_test_user(&pool).await;

        let result = repo.link_account(&user_id, "discord", "54321").await;

        assert!(result.is_ok());

        let found_account = repo
            .find_account_by_provider("discord", "54321")
            .await
            .unwrap();
        assert!(found_account.is_some());
        assert_eq!(found_account.unwrap().user_id, user_id);
    }

    #[tokio::test]
    async fn test_store_and_get_pkce_verifier() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool);

        let csrf_state = "test-csrf-state";
        let pkce_verifier = "test-pkce-verifier";
        let expires_in = Duration::hours(1);

        let result = repo
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await;
        assert!(result.is_ok());

        let retrieved_verifier = repo.get_pkce_verifier(csrf_state).await.unwrap();
        assert!(retrieved_verifier.is_some());
        assert_eq!(retrieved_verifier.unwrap(), pkce_verifier);
    }

    #[tokio::test]
    async fn test_get_pkce_verifier_not_found() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool);

        let result = repo.get_pkce_verifier("nonexistent-state").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_pkce_verifier() {
        let pool = setup_test_db().await;
        let repo = SeaORMOAuthRepository::new(pool);

        let result = repo.delete_pkce_verifier("test-state").await;
        assert!(result.is_ok());
    }
}
