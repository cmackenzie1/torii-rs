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
pub mod error;
pub mod events;
pub mod repositories;
pub mod services;
pub mod session;
pub mod storage;
pub mod user;

pub use error::Error;
pub use repositories::RepositoryProvider;
pub use services::{
    MagicLinkService, OAuthService, PasskeyService, PasswordService, SessionService, UserService,
};
pub use session::Session;
pub use storage::{NewUser, SessionStorage, UserStorage};
pub use user::{DefaultUserManager, OAuthAccount, User, UserId, UserManager};
