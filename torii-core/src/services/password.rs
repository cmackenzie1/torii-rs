use crate::{
    Error, User, UserId,
    error::AuthError,
    repositories::{PasswordRepository, UserRepository},
    services::UserService,
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
    pub async fn register_user(
        &self,
        email: &str,
        password: &str,
        name: Option<String>,
    ) -> Result<User, Error> {
        // Check if user already exists
        if (self.user_service.get_user_by_email(email).await?).is_some() {
            return Err(Error::Auth(AuthError::UserAlreadyExists));
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
