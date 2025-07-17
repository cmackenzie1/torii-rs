# Torii Mailer

A pluggable email system for the Torii authentication ecosystem, built on top of [lettre](https://docs.rs/lettre) and [askama](https://docs.rs/askama).

## Features

- **Multiple Transports**: SMTP, Sendmail, and File (for local development)
- **Template Engine**: Built-in askama templates with customization support
- **Pre-built Email Types**: Magic links, welcome emails, password resets, etc.
- **Environment Configuration**: Easy setup through environment variables
- **Local Development Friendly**: File transport saves emails as .eml files
- **Type Safe**: Leverages Rust's type system for email construction

## Quick Start

```rust
use torii_mailer::prelude::*;

// Configure from environment variables
let config = MailerConfig::from_env()?;
let transport = config.build_transport()?;
let engine = AskamaTemplateEngine::new();

// Create template context
let context = TemplateContext {
    app_name: "My App".to_string(),
    app_url: "https://myapp.com".to_string(),
    user_name: Some("John Doe".to_string()),
    user_email: Some("john@example.com".to_string()),
};

// Build and send a magic link email
let email = MagicLinkEmail::build(
    &engine,
    &config.get_from_address(),
    "john@example.com",
    "https://myapp.com/auth/magic/abc123",
    context
).await?;

transport.send_email(email).await?;
```

## Configuration

Configure the mailer using environment variables:

### SMTP Transport
```bash
MAILER_SMTP_HOST=smtp.gmail.com
MAILER_SMTP_PORT=587
MAILER_SMTP_USERNAME=your-email@gmail.com
MAILER_SMTP_PASSWORD=your-app-password
MAILER_SMTP_TLS=starttls  # none, starttls, tls
```

### File Transport (Development)
```bash
MAILER_FILE_OUTPUT_DIR=./emails
```

### Sendmail Transport
```bash
MAILER_SENDMAIL=true
MAILER_SENDMAIL_COMMAND=/usr/sbin/sendmail  # optional
```

### Common Settings
```bash
MAILER_FROM_ADDRESS=noreply@myapp.com
MAILER_FROM_NAME="My App"
MAILER_APP_NAME="My App"
MAILER_APP_URL=https://myapp.com
```

## Built-in Email Types

The crate provides pre-built email types for common authentication flows:

- **MagicLinkEmail**: Passwordless authentication links
- **WelcomeEmail**: User signup confirmation
- **PasswordResetEmail**: Password reset requests
- **PasswordChangedEmail**: Password change notifications

## Templates

Templates are built using askama and can be customized by implementing your own template engine or extending the existing ones.

### Built-in Templates

All built-in templates are responsive and follow email best practices:

- Clean, minimal design
- Mobile-friendly layout
- Accessible color contrast
- Clear call-to-action buttons

### Custom Templates

You can create custom templates by implementing the `TemplateEngine` trait or by extending the `AskamaTemplateEngine`.

## Local Development

For local development, use the file transport which saves emails as `.eml` files:

```rust
let config = MailerConfig {
    transport: TransportConfig::File {
        output_dir: PathBuf::from("./emails"),
    },
    // ... other config
};
```

You can then open the `.eml` files in your email client to preview the emails.

## Integration with Torii Core

The mailer integrates seamlessly with torii-core services:

```rust
use torii_core::services::MagicLinkService;
use torii_mailer::prelude::*;

// In your magic link service
let config = MailerConfig::from_env()?;
let transport = config.build_transport()?;
let engine = AskamaTemplateEngine::new();

// Generate magic link token
let token = magic_link_service.generate_token("user@example.com").await?;

// Send email
let context = TemplateContext {
    app_name: config.app_name.clone(),
    app_url: config.app_url.clone(),
    user_email: Some("user@example.com".to_string()),
    user_name: None,
};

let email = MagicLinkEmail::build(
    &engine,
    &config.get_from_address(),
    "user@example.com",
    &format!("{}/auth/magic/{}", config.app_url, token.token),
    context
).await?;

transport.send_email(email).await?;
```