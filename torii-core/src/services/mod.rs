//! Service layer for business logic
//!
//! This module contains concrete service implementations that encapsulate
//! authentication and user management logic.

pub mod user;
pub mod session;
pub mod password;
pub mod oauth;
pub mod passkey;
pub mod magic_link;

pub use user::UserService;
pub use session::SessionService;
pub use password::PasswordService;
pub use oauth::OAuthService;
pub use passkey::PasskeyService;
pub use magic_link::MagicLinkService;