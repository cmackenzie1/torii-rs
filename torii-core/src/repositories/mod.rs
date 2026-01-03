//! Repository traits for data access layer
//!
//! This module defines the repository interfaces that services use to interact with storage.
//! These traits provide a clean abstraction over the underlying storage implementation.
//!
//! # Trait Hierarchy
//!
//! The repository system uses a composable trait hierarchy:
//!
//! - Individual `*Repository` traits define the operations for each data domain
//! - Individual `*RepositoryProvider` traits provide access to each repository type
//! - [`RepositoryProvider`] is a supertrait combining all provider traits plus lifecycle methods
//!
//! This design allows storage backends to:
//! - Implement only the repositories they need
//! - Provide a unified interface through the full `RepositoryProvider` trait
//! - Share repository implementations across different backend types

pub mod adapter;
pub mod brute_force;
pub mod invitation;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod token;
pub mod user;

pub use adapter::{
    BruteForceProtectionRepositoryAdapter, InvitationRepositoryAdapter, OAuthRepositoryAdapter,
    PasskeyRepositoryAdapter, PasswordRepositoryAdapter, SessionRepositoryAdapter,
    TokenRepositoryAdapter, UserRepositoryAdapter,
};
pub use brute_force::BruteForceProtectionRepository;
pub use invitation::InvitationRepository;
pub use oauth::OAuthRepository;
pub use passkey::{PasskeyCredential, PasskeyRepository};
pub use password::PasswordRepository;
pub use session::SessionRepository;
pub use token::TokenRepository;
pub use user::UserRepository;

use async_trait::async_trait;

use crate::Error;

// ============================================================================
// Individual Repository Provider Traits
// ============================================================================

/// Provider trait for user repository access.
///
/// Implement this trait to provide user management functionality.
pub trait UserRepositoryProvider: Send + Sync + 'static {
    /// The user repository implementation type
    type UserRepo: UserRepository;

    /// Get the user repository
    fn user(&self) -> &Self::UserRepo;
}

/// Provider trait for session repository access.
///
/// Implement this trait to provide session management functionality.
pub trait SessionRepositoryProvider: Send + Sync + 'static {
    /// The session repository implementation type
    type SessionRepo: SessionRepository;

    /// Get the session repository
    fn session(&self) -> &Self::SessionRepo;
}

/// Provider trait for password repository access.
///
/// Implement this trait to provide password authentication functionality.
pub trait PasswordRepositoryProvider: Send + Sync + 'static {
    /// The password repository implementation type
    type PasswordRepo: PasswordRepository;

    /// Get the password repository
    fn password(&self) -> &Self::PasswordRepo;
}

/// Provider trait for OAuth repository access.
///
/// Implement this trait to provide OAuth/social login functionality.
pub trait OAuthRepositoryProvider: Send + Sync + 'static {
    /// The OAuth repository implementation type
    type OAuthRepo: OAuthRepository;

    /// Get the OAuth repository
    fn oauth(&self) -> &Self::OAuthRepo;
}

/// Provider trait for passkey repository access.
///
/// Implement this trait to provide WebAuthn/FIDO2 passkey functionality.
pub trait PasskeyRepositoryProvider: Send + Sync + 'static {
    /// The passkey repository implementation type
    type PasskeyRepo: PasskeyRepository;

    /// Get the passkey repository
    fn passkey(&self) -> &Self::PasskeyRepo;
}

/// Provider trait for token repository access.
///
/// Implement this trait to provide secure token functionality (magic links, password reset, etc.).
pub trait TokenRepositoryProvider: Send + Sync + 'static {
    /// The token repository implementation type
    type TokenRepo: TokenRepository;

    /// Get the token repository
    fn token(&self) -> &Self::TokenRepo;
}

/// Provider trait for brute force protection repository access.
///
/// Implement this trait to provide brute force attack protection functionality.
pub trait BruteForceRepositoryProvider: Send + Sync + 'static {
    /// The brute force protection repository implementation type
    type BruteForceRepo: BruteForceProtectionRepository;

    /// Get the brute force protection repository
    fn brute_force(&self) -> &Self::BruteForceRepo;
}

/// Provider trait for invitation repository access.
///
/// Implement this trait to provide user invitation functionality.
pub trait InvitationRepositoryProvider: Send + Sync + 'static {
    /// The invitation repository implementation type
    type InvitationRepo: InvitationRepository;

    /// Get the invitation repository
    fn invitation(&self) -> &Self::InvitationRepo;
}

// ============================================================================
// Unified Repository Provider Trait
// ============================================================================

/// Provider trait that storage implementations must implement to provide all repositories.
///
/// This trait is a supertrait combining all individual repository provider traits,
/// plus lifecycle methods for migrations and health checks.
///
/// # Implementing a Custom Storage Backend
///
/// To implement a custom storage backend, you need to:
/// 1. Implement each individual `*Repository` trait for your backend
/// 2. Implement each individual `*RepositoryProvider` trait
/// 3. Implement the `RepositoryProvider` trait with `migrate()` and `health_check()`
///
/// # Example
///
/// ```rust,ignore
/// use torii_core::repositories::*;
///
/// struct MyStorage { /* ... */ }
///
/// impl UserRepositoryProvider for MyStorage {
///     type UserRepo = MyUserRepository;
///     fn user(&self) -> &Self::UserRepo { &self.user_repo }
/// }
///
/// // ... implement other provider traits ...
///
/// #[async_trait]
/// impl RepositoryProvider for MyStorage {
///     async fn migrate(&self) -> Result<(), Error> { /* ... */ }
///     async fn health_check(&self) -> Result<(), Error> { /* ... */ }
/// }
/// ```
#[async_trait]
pub trait RepositoryProvider:
    UserRepositoryProvider
    + SessionRepositoryProvider
    + PasswordRepositoryProvider
    + OAuthRepositoryProvider
    + PasskeyRepositoryProvider
    + TokenRepositoryProvider
    + BruteForceRepositoryProvider
    + InvitationRepositoryProvider
{
    /// Run migrations for all repositories
    async fn migrate(&self) -> Result<(), Error>;

    /// Health check for all repositories
    async fn health_check(&self) -> Result<(), Error>;
}
