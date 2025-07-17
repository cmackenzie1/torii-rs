use crate::{Email, Mailer, MailerError};
use async_trait::async_trait;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

#[derive(Debug, Clone)]
pub struct SmtpTransport {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpTransport {
    pub fn new(transport: AsyncSmtpTransport<Tokio1Executor>) -> Self {
        Self { transport }
    }

    pub fn builder(hostname: &str) -> SmtpTransportBuilder {
        SmtpTransportBuilder::new(hostname)
    }
}

#[async_trait]
impl Mailer for SmtpTransport {
    async fn send_email(&self, email: Email) -> Result<(), MailerError> {
        let message = build_message(email)?;
        self.transport.send(message).await?;
        Ok(())
    }
}

pub struct SmtpTransportBuilder {
    hostname: String,
    port: Option<u16>,
    credentials: Option<Credentials>,
    tls: TlsConfig,
}

#[derive(Debug, Clone)]
pub enum TlsConfig {
    None,
    StartTls,
    Tls,
}

impl SmtpTransportBuilder {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            port: None,
            credentials: None,
            tls: TlsConfig::StartTls,
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn credentials(mut self, username: &str, password: &str) -> Self {
        self.credentials = Some(Credentials::new(username.to_string(), password.to_string()));
        self
    }

    pub fn tls(mut self, tls: TlsConfig) -> Self {
        self.tls = tls;
        self
    }

    pub fn no_tls(mut self) -> Self {
        self.tls = TlsConfig::None;
        self
    }

    pub fn starttls(mut self) -> Self {
        self.tls = TlsConfig::StartTls;
        self
    }

    pub fn build(self) -> Result<SmtpTransport, MailerError> {
        let mut builder = match self.tls {
            TlsConfig::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.hostname)
            }
            TlsConfig::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.hostname)?
            }
            TlsConfig::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.hostname)?,
        };

        if let Some(port) = self.port {
            builder = builder.port(port);
        }

        if let Some(credentials) = self.credentials {
            builder = builder.credentials(credentials);
        }

        Ok(SmtpTransport::new(builder.build()))
    }
}

fn build_message(email: Email) -> Result<Message, MailerError> {
    let mut message_builder = Message::builder()
        .from(email.from.parse()?)
        .subject(email.subject);

    // Add recipients
    for to in email.to {
        message_builder = message_builder.to(to.parse()?);
    }

    for cc in email.cc {
        message_builder = message_builder.cc(cc.parse()?);
    }

    for bcc in email.bcc {
        message_builder = message_builder.bcc(bcc.parse()?);
    }

    if let Some(reply_to) = email.reply_to {
        message_builder = message_builder.reply_to(reply_to.parse()?);
    }

    // Add custom headers - lettre handles this differently, we'll skip custom headers for now
    // Custom headers would need to be implemented with specific header types

    // Build body - prefer HTML over text
    let message = if let Some(html) = email.html_body {
        if let Some(text) = email.text_body {
            message_builder.multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(lettre::message::SinglePart::plain(text))
                    .singlepart(lettre::message::SinglePart::html(html)),
            )?
        } else {
            message_builder.body(html)?
        }
    } else if let Some(text) = email.text_body {
        message_builder.body(text)?
    } else {
        return Err(MailerError::Builder("No email body provided".to_string()));
    };

    Ok(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_builder() {
        let transport = SmtpTransport::builder("smtp.gmail.com")
            .port(587)
            .credentials("user@gmail.com", "password")
            .starttls()
            .build();

        assert!(transport.is_ok());
    }

    #[test]
    fn test_build_message() {
        let email = Email {
            to: vec!["recipient@example.com".to_string()],
            cc: vec![],
            bcc: vec![],
            from: "sender@example.com".to_string(),
            reply_to: None,
            subject: "Test Subject".to_string(),
            html_body: Some("<h1>Hello</h1>".to_string()),
            text_body: Some("Hello".to_string()),
            headers: std::collections::HashMap::new(),
        };

        let message = build_message(email);
        assert!(message.is_ok());
    }
}
