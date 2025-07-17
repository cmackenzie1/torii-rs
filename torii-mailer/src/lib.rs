pub mod config;
pub mod email;
pub mod email_types;
pub mod error;
pub mod mailer;
pub mod templates;
pub mod transports;

pub use config::MailerConfig;
pub use email::{Email, EmailBuilder};
pub use email_types::{MagicLinkEmail, PasswordChangedEmail, PasswordResetEmail, WelcomeEmail};
pub use error::MailerError;
pub use mailer::Mailer;
pub use templates::{AskamaTemplateEngine, TemplateContext, TemplateEngine};
pub use transports::{FileTransport, SendmailTransport, SmtpTransport};

pub mod prelude {
    pub use crate::{
        AskamaTemplateEngine, Email, EmailBuilder, FileTransport, MagicLinkEmail, Mailer,
        MailerConfig, MailerError, PasswordChangedEmail, PasswordResetEmail, SendmailTransport,
        SmtpTransport, TemplateContext, TemplateEngine, WelcomeEmail,
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_imports() {
        // Basic smoke test to ensure all imports work
    }
}
