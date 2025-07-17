use crate::MailerError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub headers: HashMap<String, String>,
}

impl Email {
    pub fn builder() -> EmailBuilder {
        EmailBuilder::default()
    }

    pub fn validate(&self) -> Result<(), MailerError> {
        if self.to.is_empty() {
            return Err(MailerError::Builder(
                "At least one recipient is required".to_string(),
            ));
        }

        if self.from.is_empty() {
            return Err(MailerError::Builder("From address is required".to_string()));
        }

        if self.subject.is_empty() {
            return Err(MailerError::Builder("Subject is required".to_string()));
        }

        if self.html_body.is_none() && self.text_body.is_none() {
            return Err(MailerError::Builder(
                "Either HTML or text body is required".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct EmailBuilder {
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    from: Option<String>,
    reply_to: Option<String>,
    subject: Option<String>,
    html_body: Option<String>,
    text_body: Option<String>,
    headers: HashMap<String, String>,
}

impl EmailBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn to<S: Into<String>>(mut self, email: S) -> Self {
        self.to.push(email.into());
        self
    }

    pub fn to_multiple<I, S>(mut self, emails: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.to.extend(emails.into_iter().map(Into::into));
        self
    }

    pub fn cc<S: Into<String>>(mut self, email: S) -> Self {
        self.cc.push(email.into());
        self
    }

    pub fn bcc<S: Into<String>>(mut self, email: S) -> Self {
        self.bcc.push(email.into());
        self
    }

    pub fn from<S: Into<String>>(mut self, email: S) -> Self {
        self.from = Some(email.into());
        self
    }

    pub fn reply_to<S: Into<String>>(mut self, email: S) -> Self {
        self.reply_to = Some(email.into());
        self
    }

    pub fn subject<S: Into<String>>(mut self, subject: S) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn html_body<S: Into<String>>(mut self, html: S) -> Self {
        self.html_body = Some(html.into());
        self
    }

    pub fn text_body<S: Into<String>>(mut self, text: S) -> Self {
        self.text_body = Some(text.into());
        self
    }

    pub fn header<K, V>(mut self, key: K, value: V) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Result<Email, MailerError> {
        let email = Email {
            to: self.to,
            cc: self.cc,
            bcc: self.bcc,
            from: self
                .from
                .ok_or_else(|| MailerError::Builder("From address is required".to_string()))?,
            reply_to: self.reply_to,
            subject: self
                .subject
                .ok_or_else(|| MailerError::Builder("Subject is required".to_string()))?,
            html_body: self.html_body,
            text_body: self.text_body,
            headers: self.headers,
        };

        email.validate()?;
        Ok(email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_builder() {
        let email = Email::builder()
            .from("sender@example.com")
            .to("recipient@example.com")
            .subject("Test Subject")
            .text_body("Test content")
            .build()
            .unwrap();

        assert_eq!(email.from, "sender@example.com");
        assert_eq!(email.to, vec!["recipient@example.com"]);
        assert_eq!(email.subject, "Test Subject");
        assert_eq!(email.text_body, Some("Test content".to_string()));
    }

    #[test]
    fn test_email_validation() {
        let result = Email::builder()
            .from("sender@example.com")
            .subject("Test")
            .build();

        assert!(result.is_err());
    }
}
