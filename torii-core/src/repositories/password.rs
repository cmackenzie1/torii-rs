use crate::{Error, UserId};
use async_trait::async_trait;

/// Repository for password-related data access
#[async_trait]
pub trait PasswordRepository: Send + Sync + 'static {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Error>;

    /// Remove a user's password hash
    async fn remove_password_hash(&self, user_id: &UserId) -> Result<(), Error>;
}
