use crate::{
    Error, User,
    error::AuthError,
    repositories::{PasswordRepository, TokenRepository, UserRepository},
    services::{PasswordService, UserService},
    storage::TokenPurpose,
};
use chrono::Duration;
use std::sync::Arc;

/// Service for password reset operations
pub struct PasswordResetService<U: UserRepository, P: PasswordRepository, T: TokenRepository> {
    user_service: Arc<UserService<U>>,
    password_service: Arc<PasswordService<U, P>>,
    token_repository: Arc<T>,
}

impl<U: UserRepository, P: PasswordRepository, T: TokenRepository> PasswordResetService<U, P, T> {
    /// Create a new PasswordResetService with the given repositories
    pub fn new(
        user_repository: Arc<U>,
        password_repository: Arc<P>,
        token_repository: Arc<T>,
    ) -> Self {
        let user_service = Arc::new(UserService::new(user_repository.clone()));
        let password_service = Arc::new(PasswordService::new(user_repository, password_repository));

        Self {
            user_service,
            password_service,
            token_repository,
        }
    }

    /// Request a password reset for the given email address
    ///
    /// This will:
    /// 1. Check if a user exists with the given email
    /// 2. Generate a secure reset token (expires in 15 minutes by default)
    ///
    /// Note: For security reasons, this method doesn't reveal whether the email exists or not.
    /// Returns the generated token if a user exists, None otherwise.
    pub async fn request_password_reset(
        &self,
        email: &str,
    ) -> Result<Option<(User, String)>, Error> {
        // Check if user exists - we don't want to reveal if email exists or not
        let user = self.user_service.get_user_by_email(email).await?;

        if let Some(user) = user {
            // Generate password reset token
            let expires_in = Duration::minutes(15);
            let reset_token = self
                .token_repository
                .create_token(&user.id, TokenPurpose::PasswordReset, expires_in)
                .await?;

            Ok(Some((user, reset_token.token)))
        } else {
            Ok(None)
        }
    }

    /// Request a password reset with custom expiration time
    pub async fn request_password_reset_with_expiration(
        &self,
        email: &str,
        expires_in: Duration,
    ) -> Result<Option<(User, String)>, Error> {
        let user = self.user_service.get_user_by_email(email).await?;

        if let Some(user) = user {
            let reset_token = self
                .token_repository
                .create_token(&user.id, TokenPurpose::PasswordReset, expires_in)
                .await?;

            Ok(Some((user, reset_token.token)))
        } else {
            Ok(None)
        }
    }

    /// Verify a password reset token without consuming it
    ///
    /// This is useful for frontend validation before showing the password reset form
    pub async fn verify_reset_token(&self, token: &str) -> Result<bool, Error> {
        self.token_repository
            .check_token(token, TokenPurpose::PasswordReset)
            .await
    }

    /// Complete the password reset process
    ///
    /// This will:
    /// 1. Verify and consume the reset token
    /// 2. Update the user's password
    ///
    /// Returns the user whose password was reset
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<User, Error> {
        // Verify and consume the token
        let secure_token = self
            .token_repository
            .verify_token(token, TokenPurpose::PasswordReset)
            .await?;

        let secure_token = secure_token.ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Get the user
        let user = self
            .user_service
            .get_user(&secure_token.user_id)
            .await?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Set the new password (admin operation - no old password required)
        self.password_service
            .set_password(&user.id, new_password)
            .await?;

        Ok(user)
    }

    /// Clean up expired reset tokens
    pub async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
        self.token_repository.cleanup_expired_tokens().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repositories::{PasswordRepository, TokenRepository, UserRepository};
    use crate::storage::{NewUser, SecureToken, TokenPurpose};
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
        async fn create(&self, new_user: NewUser) -> Result<User, Error> {
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
                let new_user = NewUser::builder().email(email.to_string()).build().unwrap();
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
    struct MockPasswordRepository {
        passwords: Arc<Mutex<HashMap<UserId, String>>>,
    }

    #[async_trait]
    impl PasswordRepository for MockPasswordRepository {
        async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error> {
            self.passwords
                .lock()
                .await
                .insert(user_id.clone(), hash.to_string());
            Ok(())
        }

        async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error> {
            Ok(self.passwords.lock().await.get(user_id).cloned())
        }

        async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error> {
            self.passwords.lock().await.remove(user_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockTokenRepository {
        tokens: Arc<Mutex<HashMap<String, SecureToken>>>,
    }

    #[async_trait]
    impl TokenRepository for MockTokenRepository {
        async fn create_token(
            &self,
            user_id: &UserId,
            purpose: TokenPurpose,
            expires_in: Duration,
        ) -> Result<SecureToken, Error> {
            let token_str = format!("token_{}", uuid::Uuid::new_v4());
            let expires_at = Utc::now() + expires_in;

            let secure_token = SecureToken {
                user_id: user_id.clone(),
                token: token_str.clone(),
                purpose,
                used_at: None,
                expires_at,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            self.tokens
                .lock()
                .await
                .insert(token_str, secure_token.clone());
            Ok(secure_token)
        }

        async fn verify_token(
            &self,
            token: &str,
            purpose: TokenPurpose,
        ) -> Result<Option<SecureToken>, Error> {
            let mut tokens = self.tokens.lock().await;
            if let Some(secure_token) = tokens.get(token) {
                if secure_token.expires_at > Utc::now()
                    && secure_token.used_at.is_none()
                    && secure_token.purpose == purpose
                {
                    let mut verified_token = secure_token.clone();
                    verified_token.used_at = Some(Utc::now());
                    verified_token.updated_at = Utc::now();
                    tokens.insert(token.to_string(), verified_token.clone());
                    Ok(Some(verified_token))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }

        async fn check_token(&self, token: &str, purpose: TokenPurpose) -> Result<bool, Error> {
            let tokens = self.tokens.lock().await;
            if let Some(secure_token) = tokens.get(token) {
                Ok(secure_token.expires_at > Utc::now()
                    && secure_token.used_at.is_none()
                    && secure_token.purpose == purpose)
            } else {
                Ok(false)
            }
        }

        async fn cleanup_expired_tokens(&self) -> Result<(), Error> {
            let mut tokens = self.tokens.lock().await;
            let now = Utc::now();
            tokens.retain(|_, token| token.expires_at > now);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_request_password_reset_existing_user() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());
        let token_repo = Arc::new(MockTokenRepository::default());

        // Create a user first
        let _user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordResetService::new(user_repo, password_repo, token_repo.clone());

        let result = service.request_password_reset("test@example.com").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        // Verify a token was created
        let tokens = token_repo.tokens.lock().await;
        assert_eq!(tokens.len(), 1);
    }

    #[tokio::test]
    async fn test_request_password_reset_nonexistent_user() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());
        let token_repo = Arc::new(MockTokenRepository::default());

        let service = PasswordResetService::new(user_repo, password_repo, token_repo.clone());

        // Should not fail even for non-existent user (prevent email enumeration)
        let result = service
            .request_password_reset("nonexistent@example.com")
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // No token should be created
        let tokens = token_repo.tokens.lock().await;
        assert_eq!(tokens.len(), 0);
    }

    #[tokio::test]
    async fn test_reset_password_success() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());
        let token_repo = Arc::new(MockTokenRepository::default());

        // Create a user first
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service =
            PasswordResetService::new(user_repo, password_repo.clone(), token_repo.clone());

        // Create a token directly for testing
        let token = token_repo
            .create_token(&user.id, TokenPurpose::PasswordReset, Duration::minutes(15))
            .await
            .unwrap();

        // Reset the password
        let result = service
            .reset_password(&token.token, "new_password123")
            .await;
        assert!(result.is_ok());

        let reset_user = result.unwrap();
        assert_eq!(reset_user.email, "test@example.com");

        // Verify password was set
        let passwords = password_repo.passwords.lock().await;
        assert!(passwords.contains_key(&user.id));
    }

    #[tokio::test]
    async fn test_verify_reset_token() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());
        let token_repo = Arc::new(MockTokenRepository::default());

        // Create a user first
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordResetService::new(user_repo, password_repo, token_repo.clone());

        // Create a token
        let token = token_repo
            .create_token(&user.id, TokenPurpose::PasswordReset, Duration::minutes(15))
            .await
            .unwrap();

        // Verify token (should not consume it)
        let is_valid = service.verify_reset_token(&token.token).await.unwrap();
        assert!(is_valid);

        // Verify token again (should still be valid since check_token doesn't consume it)
        let is_valid = service.verify_reset_token(&token.token).await.unwrap();
        assert!(is_valid);

        // Test invalid token
        let is_valid = service.verify_reset_token("invalid_token").await.unwrap();
        assert!(!is_valid);
    }

    #[tokio::test]
    async fn test_verify_then_reset_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());
        let token_repo = Arc::new(MockTokenRepository::default());

        // Create a user first
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service =
            PasswordResetService::new(user_repo, password_repo.clone(), token_repo.clone());

        // Create a token
        let token = token_repo
            .create_token(&user.id, TokenPurpose::PasswordReset, Duration::minutes(15))
            .await
            .unwrap();

        // Verify token first (should not consume it)
        let is_valid = service.verify_reset_token(&token.token).await.unwrap();
        assert!(is_valid);

        // Now reset the password (should consume the token)
        let result = service
            .reset_password(&token.token, "new_password123")
            .await;
        assert!(result.is_ok());

        // Verify token should now be false since it was consumed
        let is_valid = service.verify_reset_token(&token.token).await.unwrap();
        assert!(!is_valid);

        // Attempting to reset again should fail
        let result = service
            .reset_password(&token.token, "another_password")
            .await;
        assert!(result.is_err());
    }
}
