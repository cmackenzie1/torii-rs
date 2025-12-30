use async_trait::async_trait;
use chrono::{Duration, Utc};
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use torii_core::{Error, OAuthAccount, User, UserId, repositories::OAuthRepository};

use crate::SeaORMStorageError;
use crate::entities::{oauth, pkce_verifier, user};
use torii_core::error::StorageError;

pub struct SeaORMOAuthRepository {
    pool: DatabaseConnection,
}

impl SeaORMOAuthRepository {
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
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
        let user = user::Entity::find_by_id(user_id.to_string())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        if let Some(user) = user {
            let oauth_account = oauth::ActiveModel {
                user_id: Set(user.id),
                provider: Set(provider.to_string()),
                subject: Set(subject.to_string()),
                ..Default::default()
            };
            let oauth_account = oauth_account
                .insert(&self.pool)
                .await
                .map_err(SeaORMStorageError::Database)?;

            OAuthAccount::builder()
                .user_id(UserId::new(&oauth_account.user_id))
                .provider(oauth_account.provider)
                .subject(oauth_account.subject)
                .build()
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))
        } else {
            Err(SeaORMStorageError::UserNotFound.into())
        }
    }

    async fn find_user_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Error> {
        let oauth_account = oauth::Entity::find()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match oauth_account {
            Some(oauth_account) => {
                let user = user::Entity::find_by_id(oauth_account.user_id)
                    .one(&self.pool)
                    .await
                    .map_err(SeaORMStorageError::Database)?;
                let user = match user {
                    Some(user) => user,
                    None => return Err(SeaORMStorageError::UserNotFound.into()),
                };
                Ok(Some(user.into()))
            }
            _ => Ok(None),
        }
    }

    async fn find_account_by_provider(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        let oauth_account = oauth::Entity::find()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match oauth_account {
            Some(oauth_account) => {
                let account = OAuthAccount::builder()
                    .user_id(UserId::new(&oauth_account.user_id))
                    .provider(oauth_account.provider)
                    .subject(oauth_account.subject)
                    .build()?;
                Ok(Some(account))
            }
            None => Ok(None),
        }
    }

    async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        let user = user::Entity::find_by_id(user_id.to_string())
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        let user = match user {
            Some(user) => user,
            None => return Err(SeaORMStorageError::UserNotFound.into()),
        };

        let oauth_account = oauth::ActiveModel {
            user_id: Set(user.id),
            provider: Set(provider.to_string()),
            subject: Set(subject.to_string()),
            ..Default::default()
        };
        oauth_account
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;
        Ok(())
    }

    async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        let pkce_verifier = pkce_verifier::ActiveModel {
            csrf_state: Set(csrf_state.to_string()),
            verifier: Set(pkce_verifier.to_string()),
            expires_at: Set(Utc::now() + expires_in),
            ..Default::default()
        };
        pkce_verifier
            .insert(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;
        Ok(())
    }

    async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        let now = Utc::now();
        let pkce_verifier = pkce_verifier::Entity::find()
            .filter(pkce_verifier::Column::CsrfState.eq(csrf_state))
            .filter(pkce_verifier::Column::ExpiresAt.gt(now))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match pkce_verifier {
            Some(pkce_verifier) => Ok(Some(pkce_verifier.verifier)),
            None => Ok(None),
        }
    }

    async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
        pkce_verifier::Entity::delete_many()
            .filter(pkce_verifier::Column::CsrfState.eq(csrf_state))
            .exec(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use crate::repositories::SeaORMUserRepository;
    use sea_orm::Database;
    use sea_orm_migration::MigratorTrait;

    async fn setup_test_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&pool, None).await.unwrap();
        pool
    }

    async fn create_test_user(pool: &DatabaseConnection) -> UserId {
        let repo = SeaORMUserRepository::new(pool.clone());
        let user = repo
            .create_user("test@example.com", Some("Test User"))
            .await
            .unwrap();
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
        let repo = SeaORMOAuthRepository::new(pool.clone());

        let csrf_state = "test-state-to-delete";
        let pkce_verifier = "test-verifier";
        let expires_in = Duration::hours(1);

        // Store it first
        repo.store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
            .unwrap();

        // Verify it exists
        let retrieved = repo.get_pkce_verifier(csrf_state).await.unwrap();
        assert!(retrieved.is_some());

        // Delete it
        let result = repo.delete_pkce_verifier(csrf_state).await;
        assert!(result.is_ok());

        // Verify it's gone
        let after_delete = repo.get_pkce_verifier(csrf_state).await.unwrap();
        assert!(after_delete.is_none());
    }
}
