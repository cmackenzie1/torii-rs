#[cfg(feature = "mailer")]
pub use self::mailer_impl::*;

#[cfg(feature = "mailer")]
mod mailer_impl {
    use crate::Error;
    use async_trait::async_trait;
    use torii_mailer::prelude::*;

    #[async_trait]
    pub trait MailerService: Send + Sync {
        async fn send_magic_link_email(
            &self,
            to: &str,
            magic_link: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error>;

        async fn send_welcome_email(&self, to: &str, user_name: Option<&str>) -> Result<(), Error>;

        async fn send_password_reset_email(
            &self,
            to: &str,
            reset_link: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error>;

        async fn send_password_changed_email(
            &self,
            to: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error>;
    }

    pub struct ToriiMailerService {
        transport: Box<dyn Mailer>,
        engine: AskamaTemplateEngine,
        config: MailerConfig,
    }

    impl ToriiMailerService {
        pub fn new(config: MailerConfig) -> Result<Self, Error> {
            let transport = config.build_transport().map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;
            let engine = AskamaTemplateEngine::new();

            Ok(Self {
                transport,
                engine,
                config,
            })
        }

        pub fn from_env() -> Result<Self, Error> {
            let config = MailerConfig::from_env().map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;
            Self::new(config)
        }

        fn create_context(
            &self,
            user_name: Option<&str>,
            user_email: Option<&str>,
        ) -> TemplateContext {
            TemplateContext {
                app_name: self.config.app_name.clone(),
                app_url: self.config.app_url.clone(),
                user_name: user_name.map(|s| s.to_string()),
                user_email: user_email.map(|s| s.to_string()),
            }
        }
    }

    #[async_trait]
    impl MailerService for ToriiMailerService {
        async fn send_magic_link_email(
            &self,
            to: &str,
            magic_link: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error> {
            let context = self.create_context(user_name, Some(to));

            let email = MagicLinkEmail::build(
                &self.engine,
                &self.config.get_from_address(),
                to,
                magic_link,
                context,
            )
            .await
            .map_err(|e| Error::Storage(crate::error::StorageError::Connection(e.to_string())))?;

            self.transport.send_email(email).await.map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;

            Ok(())
        }

        async fn send_welcome_email(&self, to: &str, user_name: Option<&str>) -> Result<(), Error> {
            let context = self.create_context(user_name, Some(to));

            let email =
                WelcomeEmail::build(&self.engine, &self.config.get_from_address(), to, context)
                    .await
                    .map_err(|e| {
                        Error::Storage(crate::error::StorageError::Connection(e.to_string()))
                    })?;

            self.transport.send_email(email).await.map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;

            Ok(())
        }

        async fn send_password_reset_email(
            &self,
            to: &str,
            reset_link: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error> {
            let context = self.create_context(user_name, Some(to));

            let email = PasswordResetEmail::build(
                &self.engine,
                &self.config.get_from_address(),
                to,
                reset_link,
                context,
            )
            .await
            .map_err(|e| Error::Storage(crate::error::StorageError::Connection(e.to_string())))?;

            self.transport.send_email(email).await.map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;

            Ok(())
        }

        async fn send_password_changed_email(
            &self,
            to: &str,
            user_name: Option<&str>,
        ) -> Result<(), Error> {
            let context = self.create_context(user_name, Some(to));

            let email = PasswordChangedEmail::build(
                &self.engine,
                &self.config.get_from_address(),
                to,
                context,
            )
            .await
            .map_err(|e| Error::Storage(crate::error::StorageError::Connection(e.to_string())))?;

            self.transport.send_email(email).await.map_err(|e| {
                Error::Storage(crate::error::StorageError::Connection(e.to_string()))
            })?;

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::PathBuf;
        use torii_mailer::config::TransportConfig;
        use torii_mailer::prelude::*;

        struct MockMailer {
            sent_emails: std::sync::Arc<std::sync::Mutex<Vec<Email>>>,
        }

        impl MockMailer {
            fn new() -> Self {
                Self {
                    sent_emails: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                }
            }

            fn get_sent_emails(&self) -> Vec<Email> {
                self.sent_emails.lock().unwrap().clone()
            }
        }

        #[async_trait]
        impl Mailer for MockMailer {
            async fn send_email(&self, email: Email) -> Result<(), MailerError> {
                self.sent_emails.lock().unwrap().push(email);
                Ok(())
            }
        }

        fn create_test_config() -> MailerConfig {
            MailerConfig {
                app_name: "Test App".to_string(),
                app_url: "https://test.com".to_string(),
                from_address: "test@test.com".to_string(),
                from_name: Some("Test App".to_string()),
                transport: TransportConfig::File {
                    output_dir: PathBuf::from("/tmp"),
                },
            }
        }

        fn create_test_service() -> ToriiMailerService {
            let config = create_test_config();
            let transport = Box::new(MockMailer::new());
            let engine = AskamaTemplateEngine::new();

            ToriiMailerService {
                transport,
                engine,
                config,
            }
        }

        #[tokio::test]
        async fn test_new_service() {
            let config = create_test_config();
            let result = ToriiMailerService::new(config);
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_create_context() {
            let service = create_test_service();
            let context = service.create_context(Some("John Doe"), Some("john@example.com"));

            assert_eq!(context.app_name, "Test App");
            assert_eq!(context.app_url, "https://test.com");
            assert_eq!(context.user_name, Some("John Doe".to_string()));
            assert_eq!(context.user_email, Some("john@example.com".to_string()));
        }

        #[tokio::test]
        async fn test_create_context_none_values() {
            let service = create_test_service();
            let context = service.create_context(None, None);

            assert_eq!(context.app_name, "Test App");
            assert_eq!(context.app_url, "https://test.com");
            assert_eq!(context.user_name, None);
            assert_eq!(context.user_email, None);
        }

        #[tokio::test]
        async fn test_send_magic_link_email() {
            let service = create_test_service();
            let result = service
                .send_magic_link_email("user@example.com", "https://magic.link", Some("John"))
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_welcome_email() {
            let service = create_test_service();
            let result = service
                .send_welcome_email("user@example.com", Some("John"))
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_password_reset_email() {
            let service = create_test_service();
            let result = service
                .send_password_reset_email("user@example.com", "https://reset.link", Some("John"))
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_password_changed_email() {
            let service = create_test_service();
            let result = service
                .send_password_changed_email("user@example.com", Some("John"))
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_magic_link_email_without_name() {
            let service = create_test_service();
            let result = service
                .send_magic_link_email("user@example.com", "https://magic.link", None)
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_welcome_email_without_name() {
            let service = create_test_service();
            let result = service.send_welcome_email("user@example.com", None).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_password_reset_email_without_name() {
            let service = create_test_service();
            let result = service
                .send_password_reset_email("user@example.com", "https://reset.link", None)
                .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_send_password_changed_email_without_name() {
            let service = create_test_service();
            let result = service
                .send_password_changed_email("user@example.com", None)
                .await;

            assert!(result.is_ok());
        }
    }
}
