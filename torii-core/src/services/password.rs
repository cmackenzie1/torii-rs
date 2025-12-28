use crate::{
    Error, User, UserId,
    error::AuthError,
    repositories::{PasswordRepository, UserRepository},
    services::UserService,
    validation::validate_password,
};
use std::sync::Arc;

/// Service for password authentication operations
pub struct PasswordService<U: UserRepository, P: PasswordRepository> {
    user_service: Arc<UserService<U>>,
    password_repository: Arc<P>,
}

impl<U: UserRepository, P: PasswordRepository> PasswordService<U, P> {
    /// Create a new PasswordService with the given repositories
    pub fn new(user_repository: Arc<U>, password_repository: Arc<P>) -> Self {
        let user_service = Arc::new(UserService::new(user_repository));
        Self {
            user_service,
            password_repository,
        }
    }

    /// Register a new user with a password
    ///
    /// Returns the user whether newly created or already existing. This prevents
    /// user enumeration attacks by not revealing whether an email is already in use.
    ///
    /// **Security Note:** If the user already exists, their password is NOT updated.
    /// This is intentional to prevent account takeover attacks where an attacker
    /// could register with a victim's email and set their own password.
    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
        name: Option<String>,
    ) -> Result<User, Error> {
        // Validate password strength before any other operations
        validate_password(password)?;

        // Check if user already exists - return existing user to prevent enumeration
        if let Some(existing_user) = self.user_service.get_user_by_email(email).await? {
            // Return existing user without updating password to prevent enumeration
            // and potential account takeover
            return Ok(existing_user);
        }

        // Hash the password
        let password_hash = Self::hash_password(password)?;

        // Create the user (email validation happens in UserService)
        let user = self.user_service.create_user(email, name).await?;

        // Store the password hash
        self.password_repository
            .set_password_hash(&user.id, &password_hash)
            .await?;

        Ok(user)
    }

    /// Authenticate a user with email and password
    pub async fn authenticate(&self, email: &str, password: &str) -> Result<User, Error> {
        // Find user by email
        let user = self
            .user_service
            .get_user_by_email(email)
            .await?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Get password hash
        let password_hash = self
            .password_repository
            .get_password_hash(&user.id)
            .await?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Verify password
        if !Self::verify_password(password, &password_hash)? {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        Ok(user)
    }

    /// Change a user's password
    pub async fn change_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        // Validate new password strength before any other operations
        validate_password(new_password)?;

        // Get current password hash
        let current_hash = self
            .password_repository
            .get_password_hash(user_id)
            .await?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Verify old password
        if !Self::verify_password(old_password, &current_hash)? {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        // Hash new password
        let new_hash = Self::hash_password(new_password)?;

        // Update password hash
        self.password_repository
            .set_password_hash(user_id, &new_hash)
            .await?;

        Ok(())
    }

    /// Set a user's password (admin operation, no old password required)
    pub async fn set_password(&self, user_id: &UserId, password: &str) -> Result<(), Error> {
        // Validate password strength before setting
        validate_password(password)?;

        let password_hash = Self::hash_password(password)?;
        self.password_repository
            .set_password_hash(user_id, &password_hash)
            .await
    }

    /// Remove a user's password
    pub async fn remove_password(&self, user_id: &UserId) -> Result<(), Error> {
        self.password_repository.remove_password_hash(user_id).await
    }

    /// Hash a password using argon2
    fn hash_password(password: &str) -> Result<String, Error> {
        use password_auth::generate_hash;
        Ok(generate_hash(password))
    }

    /// Verify a password against a hash
    fn verify_password(password: &str, hash: &str) -> Result<bool, Error> {
        use password_auth::verify_password;
        Ok(verify_password(password, hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ValidationError;
    use crate::repositories::{PasswordRepository, UserRepository};
    use crate::storage::NewUser;
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
                locked_at: None,
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

    #[tokio::test]
    async fn test_register_user_rejects_weak_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        let service = PasswordService::new(user_repo.clone(), password_repo.clone());

        // Try to register with a weak password (too short)
        let result = service
            .register_user("test@example.com", "weak", None)
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation(ValidationError::InvalidPassword(_)) => {}
            e => panic!("Expected ValidationError::InvalidPassword, got {:?}", e),
        }

        // Verify no user was created
        let users = user_repo.users.lock().await;
        assert!(
            users.is_empty(),
            "No user should be created with a weak password"
        );
    }

    #[tokio::test]
    async fn test_register_user_rejects_empty_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        let service = PasswordService::new(user_repo.clone(), password_repo.clone());

        // Try to register with an empty password
        let result = service.register_user("test@example.com", "", None).await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation(ValidationError::MissingField(_)) => {}
            e => panic!("Expected ValidationError::MissingField, got {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_register_user_accepts_valid_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        let service = PasswordService::new(user_repo.clone(), password_repo.clone());

        // Register with a valid password (8+ characters)
        let result = service
            .register_user("test@example.com", "validpass123", None)
            .await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.email, "test@example.com");

        // Verify password hash was stored
        let passwords = password_repo.passwords.lock().await;
        assert!(passwords.contains_key(&user.id));
    }

    #[tokio::test]
    async fn test_set_password_rejects_weak_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        // Create a user directly
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordService::new(user_repo, password_repo.clone());

        // Try to set a weak password
        let result = service.set_password(&user.id, "short").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation(ValidationError::InvalidPassword(_)) => {}
            e => panic!("Expected ValidationError::InvalidPassword, got {:?}", e),
        }

        // Verify no password was set
        let passwords = password_repo.passwords.lock().await;
        assert!(!passwords.contains_key(&user.id));
    }

    #[tokio::test]
    async fn test_set_password_accepts_valid_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        // Create a user directly
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordService::new(user_repo, password_repo.clone());

        // Set a valid password
        let result = service.set_password(&user.id, "validpassword123").await;

        assert!(result.is_ok());

        // Verify password was set
        let passwords = password_repo.passwords.lock().await;
        assert!(passwords.contains_key(&user.id));
    }

    #[tokio::test]
    async fn test_change_password_rejects_weak_new_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        // Create a user and set their initial password
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordService::new(user_repo, password_repo.clone());

        // Set initial valid password
        service
            .set_password(&user.id, "original_password123")
            .await
            .unwrap();

        // Try to change to a weak password
        let result = service
            .change_password(&user.id, "original_password123", "weak")
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation(ValidationError::InvalidPassword(_)) => {}
            e => panic!("Expected ValidationError::InvalidPassword, got {:?}", e),
        }

        // Verify original password still works (password was not changed)
        let auth_result = service
            .authenticate("test@example.com", "original_password123")
            .await;
        assert!(auth_result.is_ok());
    }

    #[tokio::test]
    async fn test_change_password_accepts_valid_new_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let password_repo = Arc::new(MockPasswordRepository::default());

        // Create a user and set their initial password
        let user = user_repo
            .create(
                NewUser::builder()
                    .email("test@example.com".to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        let service = PasswordService::new(user_repo, password_repo.clone());

        // Set initial valid password
        service
            .set_password(&user.id, "original_password123")
            .await
            .unwrap();

        // Change to a new valid password
        let result = service
            .change_password(&user.id, "original_password123", "new_password456")
            .await;

        assert!(result.is_ok());

        // Verify new password works
        let auth_result = service
            .authenticate("test@example.com", "new_password456")
            .await;
        assert!(auth_result.is_ok());

        // Verify old password no longer works
        let auth_result = service
            .authenticate("test@example.com", "original_password123")
            .await;
        assert!(auth_result.is_err());
    }
}
