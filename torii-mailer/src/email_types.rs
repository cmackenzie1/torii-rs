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
