use crate::{Email, MailerError};
use async_trait::async_trait;

#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send_email(&self, email: Email) -> Result<(), MailerError>;
}

#[derive(Debug, Clone)]
pub struct MailerService<T: Mailer> {
    transport: T,
}

impl<T: Mailer> MailerService<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub async fn send(&self, email: Email) -> Result<(), MailerError> {
        self.transport.send_email(email).await
    }
}

#[async_trait]
impl<T: Mailer> Mailer for MailerService<T> {
    async fn send_email(&self, email: Email) -> Result<(), MailerError> {
        self.transport.send_email(email).await
    }
}
