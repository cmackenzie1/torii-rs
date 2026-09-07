//! Service implementations for the torii project
//!
//! This module contains the service functionality for the torii project.
//!
//! It includes the services that implement the repository architecture.
//!
//! The service module is designed to be used as a dependency for authentication services and storage backends.
//!

pub mod eventbus;
pub use eventbus::{EventBus, EventEmitter, EventPublisher};

#[cfg(feature = "postgres")]
pub mod postgres_events;
#[cfg(feature = "postgres")]
pub use postgres_events::PostgresEventTransport;

pub mod services;
pub use services::{
    BruteForceProtectionService, EmailVerificationService, MagicLinkService, OAuthService,
    PasskeyService, PasswordResetService, PasswordService, SessionService, UserService,
};
#[cfg(feature = "mailer")]
pub use services::{MailerService, ToriiMailerService};
