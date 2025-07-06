use crate::{
    Error, User, UserId, error::ValidationError, repositories::UserRepository, storage::NewUser,
};
use std::sync::Arc;

/// Service for user management operations
pub struct UserService<R: UserRepository> {
    repository: Arc<R>,
}

impl<R: UserRepository> UserService<R> {
    /// Create a new UserService with the given repository
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    /// Create a new user
    pub async fn create_user(&self, email: &str, name: Option<String>) -> Result<User, Error> {
        // Validate email format
        if !Self::is_valid_email(email) {
            return Err(Error::Validation(ValidationError::InvalidEmail(
                email.to_string(),
            )));
        }

        let mut builder = NewUser::builder()
            .id(UserId::new_random())
            .email(email.to_string());

        if let Some(name) = name {
            builder = builder.name(name);
        }

        let new_user = builder.build()?;

        self.repository.create(new_user).await
    }

    /// Get a user by ID
    pub async fn get_user(&self, user_id: &UserId) -> Result<Option<User>, Error> {
        self.repository.find_by_id(user_id).await
    }

    /// Get a user by email
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        self.repository.find_by_email(email).await
    }

    /// Get or create a user by email
    pub async fn get_or_create_user(&self, email: &str) -> Result<User, Error> {
        // Validate email format
        if !Self::is_valid_email(email) {
            return Err(Error::Validation(ValidationError::InvalidEmail(
                email.to_string(),
            )));
        }

        self.repository.find_or_create_by_email(email).await
    }

    /// Update a user
    pub async fn update_user(&self, user: &User) -> Result<User, Error> {
        self.repository.update(user).await
    }

    /// Delete a user
    pub async fn delete_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.repository.delete(user_id).await
    }

    /// Mark a user's email as verified
    pub async fn verify_email(&self, user_id: &UserId) -> Result<(), Error> {
        self.repository.mark_email_verified(user_id).await
    }

    /// Validate email format
    fn is_valid_email(email: &str) -> bool {
        use regex::Regex;
        let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
        email_regex.is_match(email)
    }
}
