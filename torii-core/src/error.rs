use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Plugin error: {0}")]
    Plugin(String),
    #[error("Plugin not found: {0}")]
    PluginNotFound(String),
    #[error("Plugin type mismatch: {0}")]
    PluginTypeMismatch(String),
    #[error("Unsupported auth method: {0}")]
    UnsupportedAuthMethod(String),
    #[error("Invalid credentials")]
    InvalidCredentials,
}
