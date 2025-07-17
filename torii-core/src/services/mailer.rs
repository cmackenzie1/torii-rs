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
}
