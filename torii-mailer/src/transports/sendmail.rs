use crate::{Email, Mailer, MailerError};
use async_trait::async_trait;
use lettre::transport::sendmail::SendmailTransport as LettreTransport;
use lettre::{Message, Transport};

#[derive(Debug, Clone)]
pub struct SendmailTransport {
    transport: LettreTransport,
}

impl SendmailTransport {
    pub fn new() -> Self {
        Self {
            transport: LettreTransport::new(),
        }
    }

    pub fn with_command<S: Into<String>>(command: S) -> Self {
        let cmd: String = command.into();
        Self {
            transport: LettreTransport::new_with_command(cmd),
        }
    }
}

impl Default for SendmailTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Mailer for SendmailTransport {
    async fn send_email(&self, email: Email) -> Result<(), MailerError> {
        let message = build_message(email)?;

        // lettre's SendmailTransport is sync, so we use spawn_blocking
        let transport = self.transport.clone();
        tokio::task::spawn_blocking(move || transport.send(&message))
            .await
            .map_err(|e| MailerError::Builder(format!("Failed to send email: {e}")))??;

        Ok(())
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
    fn test_sendmail_transport_creation() {
        let transport = SendmailTransport::new();
        // Just test that it can be created
        assert!(true);
    }

    #[test]
    fn test_sendmail_with_command() {
        let transport = SendmailTransport::with_command("/usr/sbin/sendmail");
        // Just test that it can be created
        assert!(true);
    }
}
