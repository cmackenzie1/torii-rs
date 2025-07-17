use thiserror::Error;

#[derive(Error, Debug)]
pub enum MailerError {
    #[error("Email transport error: {0}")]
    Transport(#[from] lettre::transport::smtp::Error),

    #[error("Email address error: {0}")]
    Address(#[from] lettre::address::AddressError),

    #[error("Email builder error: {0}")]
    Builder(String),

    #[error("Template error: {0}")]
    Template(#[from] askama::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("File transport error: {0}")]
    File(#[from] lettre::transport::file::Error),

    #[error("Sendmail transport error: {0}")]
    Sendmail(#[from] lettre::transport::sendmail::Error),

    #[error("Email message error: {0}")]
    Message(#[from] lettre::error::Error),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, MailerError>;
