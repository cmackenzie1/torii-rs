use chrono::Utc;
use sea_orm::ActiveValue::Set;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter};
use torii_core::{OAuthAccount, User};
use torii_core::{UserId, storage::OAuthStorage};

use crate::{SeaORMStorage, SeaORMStorageError};

use crate::entities::oauth;
use crate::entities::pkce_verifier;
use crate::entities::user;

impl From<oauth::Model> for OAuthAccount {
    fn from(value: oauth::Model) -> Self {
        OAuthAccount::builder()
            .user_id(UserId::new(&value.user_id))
            .provider(value.provider)
            .subject(value.subject)
            .build()
            .expect("Failed to build OAuthAccount")
    }
}

#[async_trait::async_trait]
impl OAuthStorage for SeaORMStorage {
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, torii_core::Error> {
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

            Ok(oauth_account.into())
        } else {
            Err(SeaORMStorageError::UserNotFound.into())
        }
    }

    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, torii_core::Error> {
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

    async fn get_oauth_account_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, torii_core::Error> {
        let oauth_account = oauth::Entity::find()
            .filter(oauth::Column::Provider.eq(provider))
            .filter(oauth::Column::Subject.eq(subject))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match oauth_account {
            Some(oauth_account) => Ok(Some(oauth_account.into())),
            None => Ok(None),
        }
    }

    async fn link_oauth_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), torii_core::Error> {
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
        expires_in: chrono::Duration,
    ) -> Result<(), torii_core::Error> {
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

    async fn get_pkce_verifier(
        &self,
        csrf_state: &str,
    ) -> Result<Option<String>, torii_core::Error> {
        let pkce_verifier = pkce_verifier::Entity::find()
            .filter(pkce_verifier::Column::CsrfState.eq(csrf_state))
            .one(&self.pool)
            .await
            .map_err(SeaORMStorageError::Database)?;

        match pkce_verifier {
            Some(pkce_verifier) => Ok(Some(pkce_verifier.verifier)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use sea_orm::{Database, DatabaseConnection};
    use sea_orm_migration::MigratorTrait;

    use super::*;
    use crate::migrations::Migrator;

    async fn setup_db() -> DatabaseConnection {
        let pool = Database::connect("sqlite::memory:")
            .await
            .expect("Failed to connect to test db");
        Migrator::up(&pool, None)
            .await
            .expect("Failed to run migrations");
        pool
    }

    #[tokio::test]
    async fn test_store_and_get_pkce_verifier() {
        let pool = setup_db().await;
        let storage = SeaORMStorage::new(pool);

        let csrf_state = "test_state";
        let pkce_verifier = "test_verifier";
        let expires_in = Duration::hours(1);

        // Store the verifier
        storage
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
            .expect("Failed to store PKCE verifier");

        // Retrieve the verifier
        let retrieved = storage
            .get_pkce_verifier(csrf_state)
            .await
            .expect("Failed to get PKCE verifier");

        assert_eq!(retrieved, Some(pkce_verifier.to_string()));

        // Test non-existent verifier
        let non_existent = storage
            .get_pkce_verifier("non_existent")
            .await
            .expect("Failed to query non-existent verifier");

        assert_eq!(non_existent, None);
    }

    #[tokio::test]
    async fn test_store_oauth_account() {
        let pool = setup_db().await;
        let storage = SeaORMStorage::new(pool);

        // First create a user
        let user = user::ActiveModel {
            email: Set("test@example.com".to_string()),
            name: Set(Some("Test User".to_string())),
            password_hash: Set(None),
            email_verified_at: Set(None),
            ..Default::default()
        };
        let user = user
            .insert(&storage.pool)
            .await
            .expect("Failed to create user");

        // Store OAuth account
        storage
            .create_oauth_account("google", "123456", &UserId::new(&user.id))
            .await
            .expect("Failed to store OAuth account");

        // Verify OAuth account was stored
        let oauth_account = oauth::Entity::find()
            .filter(oauth::Column::UserId.eq(&user.id))
            .one(&storage.pool)
            .await
            .expect("Failed to query OAuth account");

        assert!(oauth_account.is_some());
        let oauth_account = oauth_account.unwrap();
        assert_eq!(oauth_account.provider, "google");
        assert_eq!(oauth_account.subject, "123456");
        assert_eq!(oauth_account.user_id, user.id);

        // Test storing OAuth account for non-existent user
        let result = storage
            .create_oauth_account("non_existent", "google", &UserId::new("non_existent"))
            .await;
        assert!(result.is_err());
    }
}
