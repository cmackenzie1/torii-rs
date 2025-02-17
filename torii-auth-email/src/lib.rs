//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
use async_trait::async_trait;
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use torii_core::auth::{AuthPlugin, Credentials};
use torii_core::storage::{EmailPasswordStorage, Storage};
use torii_core::Plugin;
use torii_core::{
    storage::{NewUser, SessionStorage},
    Error, Session, User, UserId,
};

/// Email/password authentication plugin
///
/// This plugin provides email and password authentication for Torii.
///
/// Username is set to the provided email address.
///
/// Password is hashed using the `password_auth` crate using argon2.
pub struct EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage<Error = Error>,
{
    storage: Storage<U, S>,
}

impl<U, S> EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage<Error = Error>,
{
    pub fn new(storage: Storage<U, S>) -> Self {
        Self { storage }
    }
}

#[async_trait]
impl<U, S> Plugin for EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage<Error = Error>,
{
    fn name(&self) -> String {
        "email_password".to_string()
    }
}

impl<U, S> EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage<Error = Error>,
{
    pub async fn create_user(&self, email: &str, password: &str) -> Result<User, Error> {
        if !is_valid_email(email) {
            return Err(Error::InvalidEmailFormat);
        }
        if !is_valid_password(password) {
            return Err(Error::WeakPassword);
        }

        if let Some(_user) = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
        {
            tracing::debug!(email = %email, "User already exists");
            return Err(Error::UserAlreadyExists);
        }

        let new_user = NewUser::builder().email(email.to_string()).build().unwrap();
        let user = self
            .storage
            .create_user(&new_user)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        let hash = generate_hash(password);
        self.storage
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

    pub async fn change_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        if !is_valid_password(new_password) {
            return Err(Error::WeakPassword);
        }

        let stored_hash = self
            .storage
            .user_storage()
            .get_password_hash(user_id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        if stored_hash.is_none() {
            return Err(Error::InvalidCredentials);
        }

        verify_password(old_password, &stored_hash.unwrap())
            .map_err(|_| Error::InvalidCredentials)?;

        let new_hash = generate_hash(new_password);
        self.storage
            .user_storage()
            .set_password_hash(user_id, &new_hash)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        // Delete all existing sessions for this user for security
        self.storage
            .session_storage()
            .delete_sessions_for_user(user_id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        tracing::info!(
            user.id = %user_id,
            "Changed user password",
        );

        Ok(())
    }

    pub async fn login_user(&self, email: &str, password: &str) -> Result<(User, Session), Error> {
        let user_storage = self.storage.user_storage();

        let user = user_storage
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?
            .ok_or(Error::UserNotFound)?;

        let hash = user_storage
            .get_password_hash(&user.id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        if hash.is_none() {
            return Err(Error::InvalidCredentials);
        }

        verify_password(password, &hash.unwrap()).map_err(|_| Error::InvalidCredentials)?;

        let session = Session::builder()
            .user_id(user.id.clone())
            .build()
            .expect("Valid session");

        let session = self
            .storage
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

#[async_trait]
impl<U, S> AuthPlugin for EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage<Error = Error>,
{
    fn auth_method(&self) -> &str {
        "email_password"
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<(User, Session), Error> {
        match credentials {
            Credentials::EmailPassword { email, password } => {
                self.login_user(email, password).await
            }
            _ => Err(Error::InvalidCredentials),
        }
    }

    async fn validate_session(&self, session: &Session) -> Result<bool, Error> {
        let session = self
            .storage
            .get_session(&session.id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(session.is_some())
    }

    async fn logout(&self, session: &Session) -> Result<(), Error> {
        self.storage
            .session_storage()
            .delete_session(&session.id)
            .await
            .map_err(|e| Error::Storage(e.to_string()))?;

        Ok(())
    }
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

        let storage = Storage::new(user_storage.clone(), session_storage.clone());
        let mut manager = PluginManager::new(user_storage.clone(), session_storage.clone());
        manager.register(EmailPasswordPlugin::new(storage));

        user_storage
            .migrate()
            .await
            .map_err(|_| Error::Storage("Failed to migrate user storage".to_string()))?;
        session_storage
            .migrate()
            .await
            .map_err(|_| Error::Storage("Failed to migrate session storage".to_string()))?;

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
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .create_user("test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        let (user, _session) = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .login_user("test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .create_user("test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .create_user("test@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserAlreadyExists)));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_email_format() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .create_user("not-an-email", "password")
            .await;

        assert!(matches!(result, Err(Error::InvalidEmailFormat)));

        Ok(())
    }

    #[tokio::test]
    async fn test_weak_password() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .create_user("test@example.com", "123")
            .await;

        assert!(matches!(result, Err(Error::WeakPassword)));

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_password_login() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .create_user("test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .login_user("test@example.com", "wrong-password")
            .await;

        assert!(matches!(result, Err(Error::InvalidCredentials)));

        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_user_login() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .login_user("nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserNotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .create_user("test@example.com'; DROP TABLE users;--", "password")
            .await
            .expect_err("Should fail validation");

        Ok(())
    }

    #[tokio::test]
    async fn test_change_password() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;
        let plugin = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist");

        // Create initial user
        let user = plugin.create_user("test@example.com", "password").await?;

        let session = manager
            .storage()
            .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
            .await?;

        // Verify initial session exists
        let initial_session = manager
            .storage()
            .get_session(&session.id)
            .await
            .expect("Failed to get session")
            .expect("Session should exist");
        assert_eq!(initial_session.user_id, user.id);

        // Change password
        plugin
            .change_password(&user.id, "password", "new-password")
            .await?;

        // Verify old session was deleted
        let deleted_session = manager.storage().get_session(&session.id).await;
        assert!(deleted_session.is_err());

        // Verify can login with new password
        let result = plugin.login_user("test@example.com", "new-password").await;
        assert!(result.is_ok());

        // Verify can't login with old password
        let result = plugin.login_user("test@example.com", "password").await;
        assert!(matches!(result, Err(Error::InvalidCredentials)));

        Ok(())
    }
}
