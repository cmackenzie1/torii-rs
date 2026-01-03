use crate::{
    Email, MailerError,
    templates::{TemplateContext, TemplateData, TemplateEngine},
};

pub struct MagicLinkEmail;

impl MagicLinkEmail {
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        magic_link: &str,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let template_data = TemplateData::new()
            .insert("context", &context)?
            .insert("magic_link", magic_link)?;

        let html_body = engine
            .render_html("magic_link", template_data.clone())
            .await?;
        let text_body = engine.render_text("magic_link", template_data).await?;

        Email::builder()
            .from(from)
            .to(to)
            .subject(format!("Sign in to {}", context.app_name))
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

pub struct WelcomeEmail;

impl WelcomeEmail {
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let template_data = TemplateData::new().insert("context", &context)?;

        let html_body = engine.render_html("welcome", template_data.clone()).await?;
        let text_body = engine.render_text("welcome", template_data).await?;

        Email::builder()
            .from(from)
            .to(to)
            .subject(format!("Welcome to {}!", context.app_name))
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

pub struct PasswordResetEmail;

impl PasswordResetEmail {
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        reset_link: &str,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let template_data = TemplateData::new()
            .insert("context", &context)?
            .insert("reset_link", reset_link)?;

        let html_body = engine
            .render_html("password_reset", template_data.clone())
            .await?;
        let text_body = engine.render_text("password_reset", template_data).await?;

        Email::builder()
            .from(from)
            .to(to)
            .subject(format!("Reset your {} password", context.app_name))
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

pub struct PasswordChangedEmail;

impl PasswordChangedEmail {
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let template_data = TemplateData::new().insert("context", &context)?;

        let html_body = engine
            .render_html("password_changed", template_data.clone())
            .await?;
        let text_body = engine
            .render_text("password_changed", template_data)
            .await?;

        Email::builder()
            .from(from)
            .to(to)
            .subject(format!(
                "Your {} password has been changed",
                context.app_name
            ))
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

pub struct EmailVerificationEmail;

impl EmailVerificationEmail {
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        verification_link: &str,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let template_data = TemplateData::new()
            .insert("context", &context)?
            .insert("verification_link", verification_link)?;

        let html_body = engine
            .render_html("email_verification", template_data.clone())
            .await?;
        let text_body = engine
            .render_text("email_verification", template_data)
            .await?;

        Email::builder()
            .from(from)
            .to(to)
            .subject(format!("Verify your email for {}", context.app_name))
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

pub struct InvitationEmail;

impl InvitationEmail {
    /// Build an invitation email.
    ///
    /// # Arguments
    ///
    /// * `engine` - The template engine to use
    /// * `from` - The sender email address
    /// * `to` - The recipient email address (the invitee)
    /// * `invitation_link` - The link to accept the invitation
    /// * `inviter_name` - Optional name of the person who sent the invitation
    /// * `expires_in_days` - Number of days until the invitation expires
    /// * `context` - Template context with app information
    pub async fn build<T: TemplateEngine>(
        engine: &T,
        from: &str,
        to: &str,
        invitation_link: &str,
        inviter_name: Option<&str>,
        expires_in_days: i64,
        context: TemplateContext,
    ) -> Result<Email, MailerError> {
        let mut template_data = TemplateData::new()
            .insert("context", &context)?
            .insert("invitation_link", invitation_link)?
            .insert("expires_in_days", expires_in_days)?;

        if let Some(inviter) = inviter_name {
            template_data = template_data.insert("inviter_name", inviter)?;
        }

        let html_body = engine
            .render_html("invitation", template_data.clone())
            .await?;
        let text_body = engine.render_text("invitation", template_data).await?;

        let subject = if let Some(inviter) = inviter_name {
            format!("{} has invited you to join {}", inviter, context.app_name)
        } else {
            format!("You've been invited to join {}", context.app_name)
        };

        Email::builder()
            .from(from)
            .to(to)
            .subject(subject)
            .html_body(html_body)
            .text_body(text_body)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::templates::AskamaTemplateEngine;

    #[tokio::test]
    async fn test_magic_link_email() {
        let engine = AskamaTemplateEngine::new();
        let context = TemplateContext {
            app_name: "Test App".to_string(),
            app_url: "https://testapp.com".to_string(),
            user_name: Some("John Doe".to_string()),
            user_email: Some("john@example.com".to_string()),
        };

        let email = MagicLinkEmail::build(
            &engine,
            "noreply@testapp.com",
            "john@example.com",
            "https://testapp.com/magic/abc123",
            context,
        )
        .await;

        assert!(email.is_ok());
        let email = email.unwrap();
        assert_eq!(email.to, vec!["john@example.com"]);
        assert_eq!(email.from, "noreply@testapp.com");
        assert!(email.subject.contains("Test App"));
        assert!(email.html_body.is_some());
        assert!(email.text_body.is_some());
    }

    #[tokio::test]
    async fn test_welcome_email() {
        let engine = AskamaTemplateEngine::new();
        let context = TemplateContext {
            app_name: "Test App".to_string(),
            app_url: "https://testapp.com".to_string(),
            user_name: Some("Jane Doe".to_string()),
            user_email: Some("jane@example.com".to_string()),
        };

        let email =
            WelcomeEmail::build(&engine, "noreply@testapp.com", "jane@example.com", context).await;

        assert!(email.is_ok());
        let email = email.unwrap();
        assert!(email.subject.contains("Welcome"));
    }
}
