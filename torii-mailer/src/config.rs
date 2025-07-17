use crate::transports::TlsConfig;
use crate::{FileTransport, Mailer, MailerError, SendmailTransport, SmtpTransport};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailerConfig {
    pub transport: TransportConfig,
    pub from_address: String,
    pub from_name: Option<String>,
    pub app_name: String,
    pub app_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportConfig {
    Smtp {
        host: String,
        port: Option<u16>,
        username: Option<String>,
        password: Option<String>,
        tls: Option<TlsType>,
    },
    File {
        output_dir: PathBuf,
    },
    Sendmail {
        command: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsType {
    None,
    StartTls,
    Tls,
}

impl From<TlsType> for TlsConfig {
    fn from(tls_type: TlsType) -> Self {
        match tls_type {
            TlsType::None => TlsConfig::None,
            TlsType::StartTls => TlsConfig::StartTls,
            TlsType::Tls => TlsConfig::Tls,
        }
    }
}

impl MailerConfig {
    pub fn from_env() -> Result<Self, MailerError> {
        let transport = if let Ok(smtp_host) = std::env::var("MAILER_SMTP_HOST") {
            TransportConfig::Smtp {
                host: smtp_host,
                port: std::env::var("MAILER_SMTP_PORT")
                    .ok()
                    .and_then(|p| p.parse().ok()),
                username: std::env::var("MAILER_SMTP_USERNAME").ok(),
                password: std::env::var("MAILER_SMTP_PASSWORD").ok(),
                tls: std::env::var("MAILER_SMTP_TLS").ok().and_then(|t| {
                    match t.to_lowercase().as_str() {
                        "none" => Some(TlsType::None),
                        "starttls" => Some(TlsType::StartTls),
                        "tls" => Some(TlsType::Tls),
                        _ => None,
                    }
                }),
            }
        } else if let Ok(output_dir) = std::env::var("MAILER_FILE_OUTPUT_DIR") {
            TransportConfig::File {
                output_dir: PathBuf::from(output_dir),
            }
        } else if std::env::var("MAILER_SENDMAIL").is_ok() {
            TransportConfig::Sendmail {
                command: std::env::var("MAILER_SENDMAIL_COMMAND").ok(),
            }
        } else {
            // Default to file transport for development
            TransportConfig::File {
                output_dir: PathBuf::from("./emails"),
            }
        };

        Ok(Self {
            transport,
            from_address: std::env::var("MAILER_FROM_ADDRESS")
                .unwrap_or_else(|_| "noreply@example.com".to_string()),
            from_name: std::env::var("MAILER_FROM_NAME").ok(),
            app_name: std::env::var("MAILER_APP_NAME").unwrap_or_else(|_| "Your App".to_string()),
            app_url: std::env::var("MAILER_APP_URL")
                .unwrap_or_else(|_| "https://yourapp.com".to_string()),
        })
    }

    pub fn build_transport(&self) -> Result<Box<dyn Mailer>, MailerError> {
        match &self.transport {
            TransportConfig::Smtp {
                host,
                port,
                username,
                password,
                tls,
            } => {
                let mut builder = SmtpTransport::builder(host);

                if let Some(port) = port {
                    builder = builder.port(*port);
                }

                if let (Some(username), Some(password)) = (username, password) {
                    builder = builder.credentials(username, password);
                }

                if let Some(tls) = tls {
                    builder = builder.tls(tls.clone().into());
                }

                Ok(Box::new(builder.build()?))
            }
            TransportConfig::File { output_dir } => Ok(Box::new(FileTransport::new(output_dir)?)),
            TransportConfig::Sendmail { command } => {
                if let Some(command) = command {
                    Ok(Box::new(SendmailTransport::with_command(command)))
                } else {
                    Ok(Box::new(SendmailTransport::new()))
                }
            }
        }
    }

    pub fn get_from_address(&self) -> String {
        if let Some(name) = &self.from_name {
            format!("{} <{}>", name, self.from_address)
        } else {
            self.from_address.clone()
        }
    }
}

impl Default for MailerConfig {
    fn default() -> Self {
        Self {
            transport: TransportConfig::File {
                output_dir: PathBuf::from("./emails"),
            },
            from_address: "noreply@example.com".to_string(),
            from_name: None,
            app_name: "Your App".to_string(),
            app_url: "https://yourapp.com".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = MailerConfig::default();
        assert_eq!(config.from_address, "noreply@example.com");
        assert_eq!(config.app_name, "Your App");

        match config.transport {
            TransportConfig::File { output_dir } => {
                assert_eq!(output_dir, PathBuf::from("./emails"));
            }
            _ => panic!("Expected file transport"),
        }
    }

    #[test]
    fn test_get_from_address() {
        let mut config = MailerConfig::default();
        assert_eq!(config.get_from_address(), "noreply@example.com");

        config.from_name = Some("Test App".to_string());
        assert_eq!(config.get_from_address(), "Test App <noreply@example.com>");
    }

    #[test]
    fn test_build_file_transport() {
        let config = MailerConfig::default();
        let transport = config.build_transport();
        assert!(transport.is_ok());
    }
}
