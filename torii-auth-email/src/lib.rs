//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
use async_trait::async_trait;
use chrono::{Duration, Utc};
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use torii_core::session::SessionId;
use torii_core::storage::{NewUser, SessionStorage, UserStorage};
use torii_core::{Error, Plugin, Session, User};
use torii_storage_sqlite::EmailAuthStorage;

pub struct EmailPasswordPlugin;

impl EmailPasswordPlugin {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for EmailPasswordPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<U: UserStorage<Error = Error>, S: SessionStorage<Error = Error>> Plugin<U, S>
    for EmailPasswordPlugin
{
    fn name(&self) -> &'static str {
        "email_password"
    }
}

impl EmailPasswordPlugin {
    pub async fn create_user<S: EmailAuthStorage<Error = Error>>(
        &self,
        storage: &S,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        if !is_valid_email(email) {
            return Err(Error::InvalidEmailFormat);
        }
        if !is_valid_password(password) {
            return Err(Error::WeakPassword);
        }

        // TODO: Wrap this in a transaction

        if let Some(_user) = storage
            .get_user_by_email(email)
            .await
            .map_err(|_| Error::InternalServerError)?
        {
            tracing::debug!(email = %email, "User already exists");
            return Err(Error::UserAlreadyExists);
        }

        let user = storage
            .create_user(&NewUser::new_with_default_id(email.to_string()))
            .await
            .expect("Failed to create user");

        let hash = generate_hash(password);
        storage
            .set_password_hash(&user.id, &hash)
            .await
            .expect("Failed to set password");

        tracing::info!(
            user.id = %user.id,
            user.email = %user.email,
            user.name = %user.name,
            "Created user",
        );

        Ok(user)
    }

    pub async fn login_user<S: EmailAuthStorage<Error = Error>>(
        &self,
        storage: &S,
        email: &str,
        password: &str,
    ) -> Result<(User, Session), Error> {
        let user = storage
            .get_user_by_email(email)
            .await
            .map_err(|_| Error::UserNotFound)?
            .ok_or_else(|| Error::UserNotFound)?;

        let hash = storage
            .get_password_hash(&user.id)
            .await
            .map_err(|_| Error::InvalidCredentials)?;

        verify_password(password, &hash).map_err(|_| Error::InvalidCredentials)?;

        // Create a new session
        let session = Session {
            id: SessionId::new_random(),
            user_id: user.id.clone(),
            user_agent: None,
            ip_address: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
        };

        let session = storage
            .create_session(&session)
            .await
            .map_err(|_| Error::InternalServerError)?;

        tracing::info!(
            user.id = %user.id,
            user.email = %user.email,
            user.name = %user.name,
            session.id = %session.id,
            "Logged in user",
        );

        Ok((user, session))
    }
}

/// Validate an email address.
fn is_valid_email(email: &str) -> bool {
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    email_regex.is_match(email)
}

/// Validate a password.
fn is_valid_password(password: &str) -> bool {
    // TODO: Add more robust password validation
    password.len() >= 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use std::sync::Arc;
    use torii_core::PluginManager;
    use torii_storage_sqlite::SqliteStorage;

    async fn setup_plugin() -> Result<
        (
            PluginManager<SqliteStorage, SqliteStorage>,
            Arc<SqliteStorage>,
            Arc<SqliteStorage>,
        ),
        Error,
    > {
        let _ = tracing_subscriber::fmt().try_init(); // don't panic if this fails

        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");

        let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
        let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

        let mut manager = PluginManager::new(user_storage.clone(), session_storage.clone());
        manager.register(EmailPasswordPlugin);
        manager.setup().await?;

        user_storage.migrate().await?;
        session_storage.migrate().await?;

        Ok((manager, user_storage, session_storage))
    }

    #[test]
    fn test_is_valid_email() {
        // Valid email addresses
        assert!(is_valid_email("test@example.com"));
        assert!(is_valid_email("user.name@domain.co.uk"));
        assert!(is_valid_email("user+tag@example.com"));
        assert!(is_valid_email("123@domain.com"));

        // Invalid email addresses
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("not-an-email"));
        assert!(!is_valid_email("@domain.com"));
        assert!(!is_valid_email("user@"));
        assert!(!is_valid_email("user@.com"));
        assert!(!is_valid_email("user@domain"));
        assert!(!is_valid_email("user name@domain.com"));
    }

    #[test]
    fn test_is_valid_password() {
        // Valid passwords (>= 8 characters)
        assert!(is_valid_password("password123"));
        assert!(is_valid_password("12345678"));
        assert!(is_valid_password("abcdefghijklmnop"));

        // Invalid passwords (< 8 characters)
        assert!(!is_valid_password(""));
        assert!(!is_valid_password("short"));
        assert!(!is_valid_password("1234567"));
    }

    #[tokio::test]
    async fn test_create_user_and_login() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&*user_storage, "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        let (user, _session) = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .login_user(&*user_storage, "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&*user_storage, "test@example.com", "password")
            .await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&*user_storage, "test@example.com", "password")
            .await;

        assert!(matches!(user, Err(Error::UserAlreadyExists)));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_email_format() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&*user_storage, "not-an-email", "password")
            .await;

        assert!(matches!(result, Err(Error::InvalidEmailFormat)));

        Ok(())
    }

    #[tokio::test]
    async fn test_weak_password() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&*user_storage, "test@example.com", "123")
            .await;

        assert!(matches!(result, Err(Error::WeakPassword)));

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_password_login() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&*user_storage, "test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .login_user(&*user_storage, "test@example.com", "wrong-password")
            .await;

        assert!(matches!(result, Err(Error::InvalidCredentials)));

        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_user_login() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .login_user(&*user_storage, "nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserNotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let (manager, user_storage, _session_storage) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(
                &*user_storage,
                "test@example.com'; DROP TABLE users;--",
                "password",
            )
            .await
            .expect_err("Should fail validation");

        Ok(())
    }
}
