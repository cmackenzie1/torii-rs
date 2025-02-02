//! Core functionality for the torii project
//!
//! This module contains the core functionality for the torii project.
//!
//! It includes the core user and session structs, as well as the plugin system including migrations.
//!
//! The core module is designed to be used as a dependency for plugins and is not intended to be used directly by application code.
//!
//! See [`User`] for the core user struct, [`Session`] for the core session struct, and [`Plugin`] for the plugin system.
//!
//! If your plugin requires migrations to the database, you can use the [`Migration`] struct to define the migrations.
//!
pub mod error;
pub mod migration;
pub mod migrations;
pub mod plugin;
pub mod session;
pub mod user;

pub use error::Error;
pub use migration::Migration;
pub use plugin::{AuthMethod, AuthenticationRequest, Plugin, PluginManager};
pub use session::Session;
pub use user::{User, UserId};
