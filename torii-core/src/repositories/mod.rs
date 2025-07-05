//! Repository traits for data access layer
//!
//! This module defines the repository interfaces that services use to interact with storage.
//! These traits provide a clean abstraction over the underlying storage implementation.

pub mod adapter;
pub mod magic_link;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod user;

pub use adapter::{
    MagicLinkRepositoryAdapter, OAuthRepositoryAdapter, PasskeyRepositoryAdapter,
    PasswordRepositoryAdapter, SessionRepositoryAdapter, UserRepositoryAdapter,
};
pub use magic_link::MagicLinkRepository;
pub use oauth::OAuthRepository;
pub use passkey::{PasskeyCredential, PasskeyRepository};
pub use password::PasswordRepository;
pub use session::SessionRepository;
pub use user::UserRepository;

use async_trait::async_trait;

/// Provider trait that storage implementations must implement to provide all repositories
#[async_trait]
pub trait RepositoryProvider: Send + Sync + 'static {
    type User: UserRepository;
    type Session: SessionRepository;
    type Password: PasswordRepository;
    type OAuth: OAuthRepository;
    type Passkey: PasskeyRepository;
    type MagicLink: MagicLinkRepository;
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get the user repository
    fn user(&self) -> &Self::User;

    /// Get the session repository
    fn session(&self) -> &Self::Session;

    /// Get the password repository
    fn password(&self) -> &Self::Password;

    /// Get the OAuth repository
    fn oauth(&self) -> &Self::OAuth;

    /// Get the passkey repository
    fn passkey(&self) -> &Self::Passkey;

    /// Get the magic link repository
    fn magic_link(&self) -> &Self::MagicLink;

    /// Run migrations for all repositories
    async fn migrate(&self) -> Result<(), Self::Error>;

    /// Health check for all repositories
    async fn health_check(&self) -> Result<(), Self::Error>;
}
