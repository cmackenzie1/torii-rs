//! Core functionality for the torii project
//!
//! This module contains the core functionality for the torii project.
//!
//! It includes the core user and session structs, as well as the plugin system.
//!
//! The core module is designed to be used as a dependency for plugins and is not intended to be used directly by application code.
//!
//! See [`User`] for the core user struct, [`Session`] for the core session struct, and [`Plugin`] for the plugin system.
//!
pub mod error;
pub mod events;
pub mod plugin;
pub mod session;
pub mod storage;
pub mod user;

pub use error::Error;
pub use plugin::{Plugin, PluginManager};
pub use session::Session;
pub use storage::{NewUser, SessionStorage, UserStorage};
pub use user::{OAuthAccount, User, UserId};
