use crate::{Email, Mailer, MailerError};
use async_trait::async_trait;
use lettre::transport::file::FileTransport as LettreFileTransport;
use lettre::{Message, Transport};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct FileTransport {
    transport: LettreFileTransport,
    output_dir: PathBuf,
}

impl FileTransport {
    pub fn new<P: AsRef<Path>>(output_dir: P) -> Result<Self, MailerError> {
        let output_dir = output_dir.as_ref().to_path_buf();

        if !output_dir.exists() {
            std::fs::create_dir_all(&output_dir)?;
        }

        let transport = LettreFileTransport::new(&output_dir);

        Ok(Self {
            transport,
            output_dir,
        })
    }

    pub fn output_dir(&self) -> &Path {
        &self.output_dir
    }
}

#[async_trait]
impl Mailer for FileTransport {
    async fn send_email(&self, email: Email) -> Result<(), MailerError> {
        let message = build_message(email)?;

        // lettre's FileTransport is sync, so we use spawn_blocking
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_file_transport() {
        let temp_dir = tempdir().unwrap();
        let transport = FileTransport::new(temp_dir.path()).unwrap();

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

        let result = transport.send_email(email).await;
        assert!(result.is_ok());

        // Check that a file was created
        let entries = std::fs::read_dir(temp_dir.path()).unwrap();
        assert!(entries.count() > 0);
    }
}
