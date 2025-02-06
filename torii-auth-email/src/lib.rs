//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
use async_trait::async_trait;
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use torii_core::storage::Storage;
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
    fn name(&self) -> String {
        "email_password".to_string()
    }
}

impl EmailPasswordPlugin {
    pub async fn create_user<S: EmailAuthStorage<Error = Error>>(
        &self,
        storage: &Storage<S, impl SessionStorage<Error = Error>>,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        if !is_valid_email(email) {
            return Err(Error::InvalidEmailFormat);
        }
        if !is_valid_password(password) {
            return Err(Error::WeakPassword);
        }

        if let Some(_user) = storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            tracing::debug!(email = %email, "User already exists");
            return Err(Error::UserAlreadyExists);
        }

        let new_user = NewUser::builder().email(email.to_string()).build().unwrap();
        let user = storage
            .create_user(&new_user)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        let hash = generate_hash(password);
        storage
            .user_storage()
            .set_password_hash(&user.id, &hash)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

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
        storage: &Storage<S, impl SessionStorage<Error = Error>>,
        email: &str,
        password: &str,
    ) -> Result<(User, Session), Error> {
        let user = storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .ok_or(Error::UserNotFound)?;

        let hash = storage
            .user_storage()
            .get_password_hash(&user.id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        verify_password(password, &hash).map_err(|_| Error::InvalidCredentials)?;

        let session = Session::builder()
            .user_id(user.id.clone())
            .build()
            .expect("Valid session");

        let session = storage
            .create_session(&session)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

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

    async fn setup_plugin() -> Result<(PluginManager<SqliteStorage, SqliteStorage>,), Error> {
        let _ = tracing_subscriber::fmt().try_init();

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

        Ok((manager,))
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
        let (manager,) = setup_plugin().await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .unwrap()
            .create_user(manager.storage(), "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        let (user, _session) = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .unwrap()
            .login_user(manager.storage(), "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .unwrap()
            .create_user(manager.storage(), "test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .unwrap()
            .create_user(manager.storage(), "test@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserAlreadyExists)));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_email_format() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .create_user(manager.storage(), "not-an-email", "password")
            .await;

        assert!(matches!(result, Err(Error::InvalidEmailFormat)));

        Ok(())
    }

    #[tokio::test]
    async fn test_weak_password() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .create_user(manager.storage(), "test@example.com", "123")
            .await;

        assert!(matches!(result, Err(Error::WeakPassword)));

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_password_login() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .create_user(manager.storage(), "test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .login_user(manager.storage(), "test@example.com", "wrong-password")
            .await;

        assert!(matches!(result, Err(Error::InvalidCredentials)));

        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_user_login() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .login_user(manager.storage(), "nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserNotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>("email_password")
            .expect("Plugin should exist")
            .create_user(
                manager.storage(),
                "test@example.com'; DROP TABLE users;--",
                "password",
            )
            .await
            .expect_err("Should fail validation");

        Ok(())
    }
}
