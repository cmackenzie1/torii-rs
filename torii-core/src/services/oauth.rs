use crate::{
    Error, OAuthAccount, User, UserId,
    error::AuthError,
    repositories::{OAuthRepository, UserRepository},
    services::UserService,
};
use chrono::Duration;
use std::sync::Arc;

/// Service for OAuth authentication operations
pub struct OAuthService<U: UserRepository, O: OAuthRepository> {
    user_service: Arc<UserService<U>>,
    oauth_repository: Arc<O>,
}

impl<U: UserRepository, O: OAuthRepository> OAuthService<U, O> {
    /// Create a new OAuthService with the given repositories
    pub fn new(user_repository: Arc<U>, oauth_repository: Arc<O>) -> Self {
        let user_service = Arc::new(UserService::new(user_repository));
        Self {
            user_service,
            oauth_repository,
        }
    }

    /// Create or get a user from OAuth provider information
    pub async fn get_or_create_user(
        &self,
        provider: &str,
        subject: &str,
        email: &str,
        name: Option<String>,
    ) -> Result<User, Error> {
        // First try to find existing user by OAuth provider
        if let Some(user) = self
            .oauth_repository
            .find_user_by_provider(provider, subject)
            .await?
        {
            return Ok(user);
        }

        // If not found, try to find by email and link the account
        let user = if let Some(existing_user) = self.user_service.get_user_by_email(email).await? {
            // Link existing user to OAuth account
            self.oauth_repository
                .link_account(&existing_user.id, provider, subject)
                .await?;
            existing_user
        } else {
            // Create new user (email validation happens in UserService)
            let new_user = self.user_service.create_user(email, name).await?;

            // Create OAuth account
            self.oauth_repository
                .create_account(provider, subject, &new_user.id)
                .await?;

            new_user
        };

        Ok(user)
    }

    /// Link an existing user to an OAuth account
    pub async fn link_account(
        &self,
        user_id: &UserId,
        provider: &str,
        subject: &str,
    ) -> Result<(), Error> {
        // Check if this OAuth account is already linked to another user
        if (self
            .oauth_repository
            .find_user_by_provider(provider, subject)
            .await?)
            .is_some()
        {
            return Err(Error::Auth(AuthError::AccountAlreadyLinked));
        }

        self.oauth_repository
            .link_account(user_id, provider, subject)
            .await
    }

    /// Store a PKCE verifier
    pub async fn store_pkce_verifier(
        &self,
        csrf_state: &str,
        pkce_verifier: &str,
        expires_in: Duration,
    ) -> Result<(), Error> {
        self.oauth_repository
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await
    }

    /// Get and consume a PKCE verifier
    pub async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
        let verifier = self.oauth_repository.get_pkce_verifier(csrf_state).await?;

        if verifier.is_some() {
            // Delete the verifier after retrieving it (one-time use)
            self.oauth_repository
                .delete_pkce_verifier(csrf_state)
                .await?;
        }

        Ok(verifier)
    }

    /// Get OAuth account information
    pub async fn get_account(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<OAuthAccount>, Error> {
        self.oauth_repository
            .find_account_by_provider(provider, subject)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::{OAuthRepository, UserRepository};
    use crate::{User, UserId};
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Mock implementations for testing
    #[derive(Debug, Clone)]
    struct MockUser {
        id: UserId,
        email: String,
        name: Option<String>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    }

    impl From<MockUser> for User {
        fn from(user: MockUser) -> Self {
            User {
                id: user.id,
                email: user.email,
                name: user.name,
                email_verified_at: None,
                created_at: user.created_at,
                updated_at: user.updated_at,
            }
        }
    }

    #[derive(Default)]
    struct MockUserRepository {
        users: Arc<Mutex<HashMap<UserId, MockUser>>>,
        users_by_email: Arc<Mutex<HashMap<String, MockUser>>>,
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn create(&self, new_user: crate::storage::NewUser) -> Result<User, Error> {
            let user = MockUser {
                id: UserId::new_random(),
                email: new_user.email.clone(),
                name: new_user.name,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            self.users
                .lock()
                .await
                .insert(user.id.clone(), user.clone());
            self.users_by_email
                .lock()
                .await
                .insert(new_user.email, user.clone());
            Ok(user.into())
        }

        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
            Ok(self.users.lock().await.get(id).cloned().map(Into::into))
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
            Ok(self
                .users_by_email
                .lock()
                .await
                .get(email)
                .cloned()
                .map(Into::into))
        }

        async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
            if let Some(user) = self.find_by_email(email).await? {
                Ok(user)
            } else {
                let new_user = crate::storage::NewUser::builder()
                    .email(email.to_string())
                    .build()
                    .unwrap();
                self.create(new_user).await
            }
        }

        async fn update(&self, _user: &User) -> Result<User, Error> {
            unimplemented!()
        }

        async fn delete(&self, _id: &UserId) -> Result<(), Error> {
            unimplemented!()
        }

        async fn mark_email_verified(&self, _user_id: &UserId) -> Result<(), Error> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockOAuthRepository {
        accounts: Arc<Mutex<HashMap<(String, String), OAuthAccount>>>,
        user_links: Arc<Mutex<HashMap<(String, String), UserId>>>,
        pkce_verifiers: Arc<Mutex<HashMap<String, (String, DateTime<Utc>)>>>,
    }

    #[async_trait]
    impl OAuthRepository for MockOAuthRepository {
        async fn create_account(
            &self,
            provider: &str,
            subject: &str,
            user_id: &UserId,
        ) -> Result<OAuthAccount, Error> {
            let account = OAuthAccount {
                provider: provider.to_string(),
                subject: subject.to_string(),
                user_id: user_id.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            self.accounts
                .lock()
                .await
                .insert((provider.to_string(), subject.to_string()), account.clone());
            self.user_links
                .lock()
                .await
                .insert((provider.to_string(), subject.to_string()), user_id.clone());

            Ok(account)
        }

        async fn find_account_by_provider(
            &self,
            provider: &str,
            subject: &str,
        ) -> Result<Option<OAuthAccount>, Error> {
            Ok(self
                .accounts
                .lock()
                .await
                .get(&(provider.to_string(), subject.to_string()))
                .cloned())
        }

        async fn find_user_by_provider(
            &self,
            provider: &str,
            subject: &str,
        ) -> Result<Option<User>, Error> {
            if let Some(user_id) = self
                .user_links
                .lock()
                .await
                .get(&(provider.to_string(), subject.to_string()))
            {
                // This is a simplified mock - in real implementation we'd fetch from user repo
                Ok(Some(User {
                    id: user_id.clone(),
                    email: "test@example.com".to_string(),
                    name: None,
                    email_verified_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            } else {
                Ok(None)
            }
        }

        async fn link_account(
            &self,
            user_id: &UserId,
            provider: &str,
            subject: &str,
        ) -> Result<(), Error> {
            self.user_links
                .lock()
                .await
                .insert((provider.to_string(), subject.to_string()), user_id.clone());
            Ok(())
        }

        async fn store_pkce_verifier(
            &self,
            csrf_state: &str,
            pkce_verifier: &str,
            expires_in: Duration,
        ) -> Result<(), Error> {
            let expires_at = Utc::now() + expires_in;
            self.pkce_verifiers.lock().await.insert(
                csrf_state.to_string(),
                (pkce_verifier.to_string(), expires_at),
            );
            Ok(())
        }

        async fn get_pkce_verifier(&self, csrf_state: &str) -> Result<Option<String>, Error> {
            let verifiers = self.pkce_verifiers.lock().await;
            if let Some((verifier, expires_at)) = verifiers.get(csrf_state) {
                if *expires_at > Utc::now() {
                    Ok(Some(verifier.clone()))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }

        async fn delete_pkce_verifier(&self, csrf_state: &str) -> Result<(), Error> {
            self.pkce_verifiers.lock().await.remove(csrf_state);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_get_or_create_user_new_user() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo);

        let result = service
            .get_or_create_user(
                "google",
                "123",
                "test@example.com",
                Some("Test User".to_string()),
            )
            .await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.name, Some("Test User".to_string()));
    }

    #[tokio::test]
    async fn test_get_or_create_user_existing_oauth() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo.clone());

        // First create an OAuth account
        let user_id = UserId::new_random();
        oauth_repo
            .create_account("google", "123", &user_id)
            .await
            .unwrap();

        let result = service
            .get_or_create_user("google", "123", "test@example.com", None)
            .await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_link_account_success() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo);

        let user_id = UserId::new_random();
        let result = service.link_account(&user_id, "github", "456").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_link_account_already_linked() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo.clone());

        let user_id = UserId::new_random();
        // First link the account
        oauth_repo
            .create_account("github", "456", &user_id)
            .await
            .unwrap();

        // Try to link again with different user
        let other_user_id = UserId::new_random();
        let result = service.link_account(&other_user_id, "github", "456").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::Auth(AuthError::AccountAlreadyLinked)
        ));
    }

    #[tokio::test]
    async fn test_store_and_get_pkce_verifier() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo);

        let csrf_state = "csrf_123";
        let pkce_verifier = "verifier_456";
        let expires_in = Duration::minutes(10);

        // Store the verifier
        let result = service
            .store_pkce_verifier(csrf_state, pkce_verifier, expires_in)
            .await;
        assert!(result.is_ok());

        // Get the verifier
        let result = service.get_pkce_verifier(csrf_state).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(pkce_verifier.to_string()));

        // Verify it's been consumed (should be None now)
        let result = service.get_pkce_verifier(csrf_state).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_get_account() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo.clone());

        let user_id = UserId::new_random();
        oauth_repo
            .create_account("twitter", "789", &user_id)
            .await
            .unwrap();

        let result = service.get_account("twitter", "789").await;
        assert!(result.is_ok());

        let account = result.unwrap();
        assert!(account.is_some());
        assert_eq!(account.unwrap().provider, "twitter");
    }

    #[tokio::test]
    async fn test_get_account_not_found() {
        let user_repo = Arc::new(MockUserRepository::default());
        let oauth_repo = Arc::new(MockOAuthRepository::default());
        let service = OAuthService::new(user_repo, oauth_repo);

        let result = service.get_account("nonexistent", "999").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
