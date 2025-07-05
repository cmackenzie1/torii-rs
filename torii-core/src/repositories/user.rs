use crate::{Error, User, UserId, storage::NewUser};
use async_trait::async_trait;

/// Repository for user data access
#[async_trait]
pub trait UserRepository: Send + Sync + 'static {
    /// Create a new user
    async fn create(&self, user: NewUser) -> Result<User, Error>;

    /// Find a user by ID
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error>;

    /// Find a user by email
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error>;

    /// Create a user if it doesn't exist, otherwise return the existing user
    async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error>;

    /// Update an existing user
    async fn update(&self, user: &User) -> Result<User, Error>;

    /// Delete a user by ID
    async fn delete(&self, id: &UserId) -> Result<(), Error>;

    /// Mark a user's email as verified
    async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error>;
}
