//! Service layer for business logic
//!
//! This module contains concrete service implementations that encapsulate
//! authentication and user management logic.

pub mod magic_link;
pub mod oauth;
pub mod passkey;
pub mod password;
pub mod session;
pub mod user;

pub use magic_link::MagicLinkService;
pub use oauth::OAuthService;
pub use passkey::PasskeyService;
pub use password::PasswordService;
pub use session::SessionService;
pub use user::UserService;
