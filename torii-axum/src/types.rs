use serde::{Deserialize, Serialize};
use torii::{Session, User};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyMagicTokenRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResetTokenRequest {
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub user: User,
    pub session: Session,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub user: User,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionResponse {
    pub session: Session,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MagicLinkResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordResetResponse {
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResetTokenResponse {
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: CookieSameSite,
    pub path: String,
    /// Optional max age for the cookie. If set, the cookie will expire after this duration.
    /// If not set, cookies will use the session's `expires_at` field to calculate the max age.
    pub max_age: Option<chrono::Duration>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "session_id".to_string(),
            http_only: true,
            secure: true,
            same_site: CookieSameSite::Lax,
            path: "/".to_string(),
            max_age: None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub enum CookieSameSite {
    Strict,
    #[default]
    Lax,
    None,
}

/// Configuration for verification links sent via email.
///
/// This configuration is used to build URLs for magic link authentication
/// and password reset flows. The URLs are constructed by combining the
/// hostname with the path prefix and the specific route.
///
/// # Example
///
/// ```rust
/// use torii_axum::LinkConfig;
///
/// let config = LinkConfig::new("https://example.com");
/// // Uses default path_prefix "/auth"
/// // Magic link URL: https://example.com/auth/magic-link/verify?token=...
/// // Password reset URL: https://example.com/auth/password/reset?token=...
///
/// let config = LinkConfig::new("https://example.com")
///     .with_path_prefix("/api/v1/auth");
/// // Magic link URL: https://example.com/api/v1/auth/magic-link/verify?token=...
/// ```
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// The base hostname/URL for the application (e.g., "https://example.com")
    pub hostname: String,
    /// Path prefix where auth routes are mounted (defaults to "/auth")
    pub path_prefix: String,
}

impl LinkConfig {
    /// Create a new LinkConfig with the given hostname.
    ///
    /// The path prefix defaults to "/auth".
    pub fn new(hostname: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            path_prefix: "/auth".to_string(),
        }
    }

    /// Set a custom path prefix for the auth routes.
    ///
    /// Use this if you mount the auth routes at a different path than "/auth".
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.path_prefix = prefix.into();
        self
    }

    /// Build the magic link verification URL with the given token.
    ///
    /// Returns a URL in the format: `{hostname}{path_prefix}/magic-link/verify?token={token}`
    pub fn magic_link_url(&self, token: &str) -> String {
        format!(
            "{}{}/magic-link/verify?token={}",
            self.hostname.trim_end_matches('/'),
            self.path_prefix,
            token
        )
    }

    /// Build the password reset URL with the given token.
    ///
    /// Returns a URL in the format: `{hostname}{path_prefix}/password/reset?token={token}`
    pub fn password_reset_url(&self, token: &str) -> String {
        format!(
            "{}{}/password/reset?token={}",
            self.hostname.trim_end_matches('/'),
            self.path_prefix,
            token
        )
    }
}

impl CookieConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            http_only: true,
            secure: true,
            same_site: CookieSameSite::Lax,
            path: "/".to_string(),
            max_age: None,
        }
    }

    pub fn development() -> Self {
        Self {
            name: "session_id".to_string(),
            http_only: true,
            secure: false,
            same_site: CookieSameSite::Lax,
            path: "/".to_string(),
            max_age: None,
        }
    }

    /// Set a custom max age for the cookie.
    ///
    /// If not set, the cookie will use the session's `expires_at` field to calculate the max age.
    pub fn with_max_age(mut self, max_age: chrono::Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }
}
