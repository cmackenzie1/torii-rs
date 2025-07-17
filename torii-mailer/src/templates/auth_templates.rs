use crate::{MailerError, templates::TemplateData};
use askama::Template;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateContext {
    pub app_name: String,
    pub app_url: String,
    pub user_email: Option<String>,
    pub user_name: Option<String>,
}

impl Default for TemplateContext {
    fn default() -> Self {
        Self {
            app_name: "Your App".to_string(),
            app_url: "https://yourapp.com".to_string(),
            user_email: None,
            user_name: None,
        }
    }
}

#[derive(Template)]
#[template(
    source = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Magic Link - {{ app_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .button { display: inline-block; padding: 12px 24px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ app_name }}</h1>
        </div>
        
        <h2>Sign In to Your Account</h2>
        
        <p>{% if let Some(name) = user_name %}Hello {{ name }},{% else %}Hello,{% endif %}</p>
        
        <p>Click the button below to sign in to your account. This link will expire in 15 minutes for security.</p>
        
        <div style="text-align: center;">
            <a href="{{ magic_link }}" class="button">Sign In</a>
        </div>
        
        <p>Or copy and paste this URL into your browser:</p>
        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace;">{{ magic_link }}</p>
        
        <p>If you didn't request this email, you can safely ignore it.</p>
        
        <div class="footer">
            <p>This email was sent by {{ app_name }}. If you have any questions, please contact our support team.</p>
        </div>
    </div>
</body>
</html>
"#,
    ext = "html"
)]
pub struct MagicLinkTemplate {
    pub app_name: String,
    pub app_url: String,
    pub user_name: Option<String>,
    pub magic_link: String,
}

impl MagicLinkTemplate {
    pub fn from_data(data: TemplateData) -> Result<Self, MailerError> {
        let context: TemplateContext = data
            .get("context")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let magic_link = data
            .get("magic_link")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MailerError::Builder("magic_link is required".to_string()))?
            .to_string();

        Ok(Self {
            app_name: context.app_name,
            app_url: context.app_url,
            user_name: context.user_name,
            magic_link,
        })
    }
}

#[derive(Template)]
#[template(
    source = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome - {{ app_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .button { display: inline-block; padding: 12px 24px; background-color: #28a745; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ app_name }}</h1>
        </div>
        
        <h2>Welcome to {{ app_name }}!</h2>
        
        <p>{% if let Some(name) = user_name %}Hello {{ name }},{% else %}Hello,{% endif %}</p>
        
        <p>We're excited to have you on board! Your account has been successfully created and you're ready to get started.</p>
        
        <div style="text-align: center;">
            <a href="{{ app_url }}" class="button">Get Started</a>
        </div>
        
        <p>Here are a few things you can do to get started:</p>
        <ul>
            <li>Complete your profile</li>
            <li>Explore the features</li>
            <li>Connect with other users</li>
        </ul>
        
        <p>If you have any questions, don't hesitate to reach out to our support team.</p>
        
        <div class="footer">
            <p>Thanks for joining {{ app_name }}!</p>
        </div>
    </div>
</body>
</html>
"#,
    ext = "html"
)]
pub struct WelcomeTemplate {
    pub app_name: String,
    pub app_url: String,
    pub user_name: Option<String>,
}

impl WelcomeTemplate {
    pub fn from_data(data: TemplateData) -> Result<Self, MailerError> {
        let context: TemplateContext = data
            .get("context")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(Self {
            app_name: context.app_name,
            app_url: context.app_url,
            user_name: context.user_name,
        })
    }
}

#[derive(Template)]
#[template(
    source = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Your Password - {{ app_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .button { display: inline-block; padding: 12px 24px; background-color: #dc3545; color: white; text-decoration: none; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ app_name }}</h1>
        </div>
        
        <h2>Reset Your Password</h2>
        
        <p>{% if let Some(name) = user_name %}Hello {{ name }},{% else %}Hello,{% endif %}</p>
        
        <p>We received a request to reset your password. Click the button below to create a new password:</p>
        
        <div style="text-align: center;">
            <a href="{{ reset_link }}" class="button">Reset Password</a>
        </div>
        
        <p>Or copy and paste this URL into your browser:</p>
        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace;">{{ reset_link }}</p>
        
        <p>This link will expire in 1 hour for security reasons.</p>
        
        <p>If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.</p>
        
        <div class="footer">
            <p>For security, this request was made from {{ app_name }}. If you have any concerns, please contact our support team.</p>
        </div>
    </div>
</body>
</html>
"#,
    ext = "html"
)]
pub struct PasswordResetTemplate {
    pub app_name: String,
    pub app_url: String,
    pub user_name: Option<String>,
    pub reset_link: String,
}

impl PasswordResetTemplate {
    pub fn from_data(data: TemplateData) -> Result<Self, MailerError> {
        let context: TemplateContext = data
            .get("context")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let reset_link = data
            .get("reset_link")
            .and_then(|v| v.as_str())
            .ok_or_else(|| MailerError::Builder("reset_link is required".to_string()))?
            .to_string();

        Ok(Self {
            app_name: context.app_name,
            app_url: context.app_url,
            user_name: context.user_name,
            reset_link,
        })
    }
}

#[derive(Template)]
#[template(
    source = r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed - {{ app_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .alert { background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ app_name }}</h1>
        </div>
        
        <h2>Password Successfully Changed</h2>
        
        <p>{% if let Some(name) = user_name %}Hello {{ name }},{% else %}Hello,{% endif %}</p>
        
        <div class="alert">
            <strong>Your password has been successfully changed.</strong>
        </div>
        
        <p>This is a confirmation that your account password was recently changed. If you made this change, no further action is required.</p>
        
        <p><strong>If you did not make this change:</strong></p>
        <ul>
            <li>Your account may have been compromised</li>
            <li>Please contact our support team immediately</li>
            <li>Consider reviewing your recent account activity</li>
        </ul>
        
        <p>For your security, we recommend:</p>
        <ul>
            <li>Using a strong, unique password</li>
            <li>Enabling two-factor authentication if available</li>
            <li>Regularly reviewing your account activity</li>
        </ul>
        
        <div class="footer">
            <p>This notification was sent for your security by {{ app_name }}. If you have any concerns, please contact our support team immediately.</p>
        </div>
    </div>
</body>
</html>
"#,
    ext = "html"
)]
pub struct PasswordChangedTemplate {
    pub app_name: String,
    pub app_url: String,
    pub user_name: Option<String>,
}

impl PasswordChangedTemplate {
    pub fn from_data(data: TemplateData) -> Result<Self, MailerError> {
        let context: TemplateContext = data
            .get("context")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        Ok(Self {
            app_name: context.app_name,
            app_url: context.app_url,
            user_name: context.user_name,
        })
    }
}
