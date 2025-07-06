use crate::{
    Error, User,
    repositories::{MagicLinkRepository, UserRepository},
    services::UserService,
    storage::MagicToken,
};
use chrono::Duration;
use std::sync::Arc;

/// Service for magic link authentication operations
pub struct MagicLinkService<U: UserRepository, M: MagicLinkRepository> {
    user_service: Arc<UserService<U>>,
    magic_link_repository: Arc<M>,
}

impl<U: UserRepository, M: MagicLinkRepository> MagicLinkService<U, M> {
    /// Create a new MagicLinkService with the given repositories
    pub fn new(user_repository: Arc<U>, magic_link_repository: Arc<M>) -> Self {
        let user_service = Arc::new(UserService::new(user_repository));
        Self {
            user_service,
            magic_link_repository,
        }
    }

    /// Generate a magic token for a user
    pub async fn generate_token(&self, email: &str) -> Result<MagicToken, Error> {
        // Ensure user exists (or create them) - email validation happens in UserService
        let _user = self.user_service.get_or_create_user(email).await?;

        // Generate the token with default expiration (15 minutes)
        let expires_in = Duration::minutes(15);
        self.magic_link_repository
            .create_token(email, expires_in)
            .await
    }

    /// Generate a magic token with custom expiration
    pub async fn generate_token_with_expiration(
        &self,
        email: &str,
        expires_in: Duration,
    ) -> Result<MagicToken, Error> {
        // Ensure user exists (or create them) - email validation happens in UserService
        let _user = self.user_service.get_or_create_user(email).await?;

        self.magic_link_repository
            .create_token(email, expires_in)
            .await
    }

    /// Verify a magic token and return the associated user
    pub async fn verify_token(&self, token: &str) -> Result<Option<User>, Error> {
        // Verify and consume the token
        let email = self.magic_link_repository.verify_token(token).await?;

        if let Some(email) = email {
            // Get the user by email
            let user = self.user_service.get_user_by_email(&email).await?;
            Ok(user)
        } else {
            Ok(None)
        }
    }

    /// Clean up expired tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.magic_link_repository.cleanup_expired_tokens().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::{MagicLinkRepository, UserRepository};
    use crate::storage::MagicToken;
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
    struct MockMagicLinkRepository {
        tokens: Arc<Mutex<HashMap<String, (String, DateTime<Utc>)>>>,
    }

    #[async_trait]
    impl MagicLinkRepository for MockMagicLinkRepository {
        async fn create_token(
            &self,
            email: &str,
            expires_in: Duration,
        ) -> Result<MagicToken, Error> {
            let token = "test_token_123".to_string();
            let expires_at = Utc::now() + expires_in;

            self.tokens
                .lock()
                .await
                .insert(token.clone(), (email.to_string(), expires_at));

            Ok(MagicToken {
                user_id: UserId::new_random(),
                token,
                used_at: None,
                expires_at,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        }

        async fn verify_token(&self, token: &str) -> Result<Option<String>, Error> {
            let mut tokens = self.tokens.lock().await;
            if let Some((email, expires_at)) = tokens.get(token) {
                if *expires_at > Utc::now() {
                    let email = email.clone();
                    tokens.remove(token); // Consume the token
                    Ok(Some(email))
                } else {
                    tokens.remove(token); // Remove expired token
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }

        async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
            let mut tokens = self.tokens.lock().await;
            let now = Utc::now();
            tokens.retain(|_, (_, expires_at)| *expires_at > now);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_generate_token() {
        let user_repo = Arc::new(MockUserRepository::default());
        let magic_link_repo = Arc::new(MockMagicLinkRepository::default());
        let service = MagicLinkService::new(user_repo, magic_link_repo);

        let result = service.generate_token("test@example.com").await;
        assert!(result.is_ok());

        let token = result.unwrap();
        // MagicToken doesn't have email field directly
        assert_eq!(token.token, "test_token_123");
    }

    #[tokio::test]
    async fn test_generate_token_with_expiration() {
        let user_repo = Arc::new(MockUserRepository::default());
        let magic_link_repo = Arc::new(MockMagicLinkRepository::default());
        let service = MagicLinkService::new(user_repo, magic_link_repo);

        let expires_in = Duration::minutes(30);
        let result = service
            .generate_token_with_expiration("test@example.com", expires_in)
            .await;
        assert!(result.is_ok());

        let token = result.unwrap();
        // MagicToken doesn't have email field directly
    }

    #[tokio::test]
    async fn test_verify_token_success() {
        let user_repo = Arc::new(MockUserRepository::default());
        let magic_link_repo = Arc::new(MockMagicLinkRepository::default());
        let service = MagicLinkService::new(user_repo, magic_link_repo);

        // First generate a token
        let token = service.generate_token("test@example.com").await.unwrap();

        // Then verify it
        let result = service.verify_token(&token.token).await;
        assert!(result.is_ok());

        let user = result.unwrap();
        assert!(user.is_some());
        assert_eq!(user.unwrap().email, "test@example.com");
    }

    #[tokio::test]
    async fn test_verify_token_not_found() {
        let user_repo = Arc::new(MockUserRepository::default());
        let magic_link_repo = Arc::new(MockMagicLinkRepository::default());
        let service = MagicLinkService::new(user_repo, magic_link_repo);

        let result = service.verify_token("invalid_token").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_cleanup_expired_tokens() {
        let user_repo = Arc::new(MockUserRepository::default());
        let magic_link_repo = Arc::new(MockMagicLinkRepository::default());
        let service = MagicLinkService::new(user_repo, magic_link_repo);

        let result = service.cleanup_expired_tokens().await;
        assert!(result.is_ok());
    }
}
