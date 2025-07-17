use crate::{MailerError, templates::TemplateData};
use askama::Template;
use async_trait::async_trait;
use std::path::Path;

#[async_trait]
pub trait TemplateEngine: Send + Sync {
    async fn render(&self, template_name: &str, data: TemplateData) -> Result<String, MailerError>;
    async fn render_html(
        &self,
        template_name: &str,
        data: TemplateData,
    ) -> Result<String, MailerError>;
    async fn render_text(
        &self,
        template_name: &str,
        data: TemplateData,
    ) -> Result<String, MailerError>;
}

#[derive(Debug, Clone)]
pub struct AskamaTemplateEngine {
    #[allow(dead_code)]
    template_dir: Option<std::path::PathBuf>,
}

impl AskamaTemplateEngine {
    pub fn new() -> Self {
        Self { template_dir: None }
    }

    pub fn with_template_dir<P: AsRef<Path>>(template_dir: P) -> Self {
        Self {
            template_dir: Some(template_dir.as_ref().to_path_buf()),
        }
    }
}

impl Default for AskamaTemplateEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TemplateEngine for AskamaTemplateEngine {
    async fn render(&self, template_name: &str, data: TemplateData) -> Result<String, MailerError> {
        self.render_html(template_name, data).await
    }

    async fn render_html(
        &self,
        template_name: &str,
        data: TemplateData,
    ) -> Result<String, MailerError> {
        // For built-in templates, we use the compiled askama templates
        // For custom templates, we would load from the template directory
        match template_name {
            "magic_link" => {
                let template = crate::templates::MagicLinkTemplate::from_data(data)?;
                Ok(template.render()?)
            }
            "welcome" => {
                let template = crate::templates::WelcomeTemplate::from_data(data)?;
                Ok(template.render()?)
            }
            "password_reset" => {
                let template = crate::templates::PasswordResetTemplate::from_data(data)?;
                Ok(template.render()?)
            }
            "password_changed" => {
                let template = crate::templates::PasswordChangedTemplate::from_data(data)?;
                Ok(template.render()?)
            }
            _ => Err(MailerError::Template(askama::Error::Fmt(std::fmt::Error))),
        }
    }

    async fn render_text(
        &self,
        template_name: &str,
        data: TemplateData,
    ) -> Result<String, MailerError> {
        // For simplicity, we'll generate text versions from HTML
        // In a more sophisticated implementation, we'd have separate text templates
        let html = self.render_html(template_name, data).await?;

        // Basic HTML to text conversion (remove tags)
        let text = html
            .replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("<br />", "\n")
            .replace("</p>", "\n\n")
            .replace("</div>", "\n")
            .replace("</h1>", "\n\n")
            .replace("</h2>", "\n\n")
            .replace("</h3>", "\n\n");

        // Remove all HTML tags
        let text = regex::Regex::new(r"<[^>]*>")
            .map_err(|e| MailerError::Builder(format!("Regex error: {e}")))?
            .replace_all(&text, "");

        // Clean up extra whitespace
        let text = regex::Regex::new(r"\n\s*\n")
            .map_err(|e| MailerError::Builder(format!("Regex error: {e}")))?
            .replace_all(&text, "\n\n");

        Ok(text.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_template_engine() {
        let engine = AskamaTemplateEngine::new();
        let context = crate::templates::TemplateContext {
            app_name: "Test App".to_string(),
            app_url: "https://testapp.com".to_string(),
            user_name: Some("John Doe".to_string()),
            user_email: Some("john@example.com".to_string()),
        };
        let data = TemplateData::new()
            .insert("context", &context)
            .unwrap()
            .insert("magic_link", "https://example.com/magic/abc123")
            .unwrap();

        let result = engine.render("magic_link", data).await;
        assert!(result.is_ok());

        let html = result.unwrap();
        assert!(html.contains("https://example.com/magic/abc123"));
        assert!(html.contains("Test App"));
    }
}
