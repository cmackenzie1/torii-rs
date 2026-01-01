//! Core functionality for the torii project
//!
//! This module contains the core functionality for the torii project.
//!
//! It includes the core user and session structs, as well as the service and repository architecture.
//!
//! The core module is designed to be used as a dependency for authentication services and storage backends.
//!
//! See [`User`] for the core user struct, [`Session`] for the core session struct, and [`RepositoryProvider`] for the storage abstraction.
//!
pub mod crypto;
pub mod error;
pub mod events;
pub mod id;
pub mod repositories;
pub mod services;
pub mod session;
pub mod storage;
pub mod user;
pub mod validation;

pub use error::Error;
pub use events::UnlockReason;
pub use repositories::RepositoryProvider;
pub use services::{
    BruteForceProtectionService, EmailVerificationService, MagicLinkService, OAuthService,
    PasskeyService, PasswordResetService, PasswordService, SessionService, UserService,
};
#[cfg(feature = "mailer")]
pub use services::{MailerService, ToriiMailerService};
pub use session::{
    JwtAlgorithm, JwtClaims, JwtConfig, JwtMetadata, JwtSessionProvider, OpaqueSessionProvider,
    Session, SessionProvider, SessionToken,
};
pub use storage::{
    AttemptStats, BruteForceProtectionConfig, FailedLoginAttempt, LockoutStatus, NewUser,
    SecureToken, TokenPurpose,
};
pub use user::{OAuthAccount, User, UserId, UserManager};
