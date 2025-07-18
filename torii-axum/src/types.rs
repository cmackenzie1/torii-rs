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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
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
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "session_id".to_string(),
            http_only: true,
            secure: true,
            same_site: CookieSameSite::Lax,
            path: "/".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum CookieSameSite {
    Strict,
    Lax,
    None,
}

impl Default for CookieSameSite {
    fn default() -> Self {
        Self::Lax
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
        }
    }

    pub fn development() -> Self {
        Self {
            name: "session_id".to_string(),
            http_only: true,
            secure: false,
            same_site: CookieSameSite::Lax,
            path: "/".to_string(),
        }
    }
}
