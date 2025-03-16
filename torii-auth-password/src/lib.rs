//! A plugin for Torii that provides email and password authentication.
//!
//! This plugin allows users to register and authenticate using an email address and password.
//! It handles password hashing, validation.
//!
//! # Usage
//!
//! ```rust,no_run
//! use torii_auth_password::PasswordPlugin;
//! use torii_storage_sqlite::SqliteStorage;
//! use torii_core::{PluginManager, DefaultUserManager};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let pool = sqlx::SqlitePool::connect("sqlite::memory:").await?;
//! // Initialize storage
//! let storage = Arc::new(SqliteStorage::new(pool.clone()));
//! let session_storage = Arc::new(SqliteStorage::new(pool.clone()));
//!
//! // Create user manager
//! let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));
//!
//! // Create password plugin
//! let plugin = PasswordPlugin::new(user_manager.clone(), storage.clone());
//!
//! // Register plugin with plugin manager
//! let mut manager = PluginManager::new(storage.clone(), session_storage.clone());
//! manager.register_plugin(plugin);
//!
//! // Register a new user
//! let plugin = manager.get_plugin::<PasswordPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>("password").unwrap();
//! let user = plugin.register_user_with_password("user@example.com", "password123", None).await?;
//!
//! // Login an existing user
//! let user = plugin.login_user_with_password("user@example.com", "password123").await?;
//! # Ok(())
//! # }
//! ```
//!
//! The password plugin requires:
//! 1. A UserManager implementation for user management
//! 2. A storage implementation that implements the [`PasswordStorage`] trait
//!
//! # Features
//!
//! - User registration with email and password
//! - Password hashing and validation
//! - Optional email verification
//! - Event emission for authentication events

use std::sync::Arc;

use chrono::{DateTime, Utc};
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use torii_core::{
    Error, NewUser, Plugin, User, UserId, UserManager,
    error::{AuthError, StorageError, ValidationError},
    events::{Event, EventBus},
    storage::PasswordStorage,
};

pub struct PasswordPlugin<M, S>
where
    M: UserManager,
    S: PasswordStorage,
{
    user_manager: Arc<M>,
    password_storage: Arc<S>,
    event_bus: Option<EventBus>,
}

impl<M, S> PasswordPlugin<M, S>
where
    M: UserManager,
    S: PasswordStorage,
{
    pub fn new(user_manager: Arc<M>, password_storage: Arc<S>) -> Self {
        Self {
            user_manager,
            password_storage,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }
}

impl<M, S> Plugin for PasswordPlugin<M, S>
where
    M: UserManager,
    S: PasswordStorage,
{
    fn name(&self) -> String {
        "password".to_string()
    }
}

impl<M, S> PasswordPlugin<M, S>
where
    M: UserManager,
    S: PasswordStorage,
{
    pub async fn register_user_with_password(
        &self,
        email: &str,
        password: &str,
        email_verified_at: Option<DateTime<Utc>>,
    ) -> Result<User, Error> {
        if !is_valid_email(email) {
            return Err(Error::Validation(ValidationError::InvalidEmail));
        }
        if !is_valid_password(password) {
            return Err(Error::Validation(ValidationError::WeakPassword));
        }

        if let Some(_user) = self.user_manager.get_user_by_email(email).await? {
            tracing::debug!(email = %email, "User already exists");
            return Err(Error::Auth(AuthError::UserAlreadyExists));
        }

        let new_user = NewUser::builder()
            .email(email.to_string())
            .email_verified_at(email_verified_at)
            .build()
            .unwrap();
        let user = self.user_manager.create_user(&new_user).await?;

        let hash = generate_hash(password);
        self.password_storage
            .set_password_hash(&user.id, &hash)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        tracing::info!(
            user.id = %user.id,
            user.email = %user.email,
            user.name = ?user.name,
            "Created user",
        );

        self.emit_event(&Event::UserCreated(user.clone())).await?;

        Ok(user)
    }

    pub async fn change_user_password(
        &self,
        user_id: &UserId,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), Error> {
        if !is_valid_password(new_password) {
            return Err(Error::Validation(ValidationError::WeakPassword));
        }

        let user = self
            .user_manager
            .get_user(user_id)
            .await?
            .ok_or(Error::Auth(AuthError::UserNotFound))?;

        let stored_hash = self
            .password_storage
            .get_password_hash(user_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        if stored_hash.is_none() {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        verify_password(old_password, &stored_hash.unwrap())
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        let new_hash = generate_hash(new_password);
        self.password_storage
            .set_password_hash(user_id, &new_hash)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        tracing::info!(
            user.id = %user_id,
            "Changed user password",
        );

        self.emit_event(&Event::UserUpdated(user)).await?;

        Ok(())
    }

    pub async fn login_user_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        let user = self
            .user_manager
            .get_user_by_email(email)
            .await?
            .ok_or(Error::Auth(AuthError::UserNotFound))?;

        if !user.is_email_verified() {
            return Err(Error::Auth(AuthError::EmailNotVerified));
        }

        let hash = self
            .password_storage
            .get_password_hash(&user.id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        if hash.is_none() {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        verify_password(password, &hash.unwrap())
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        Ok(user)
    }

    async fn emit_event(&self, event: &Event) -> Result<(), Error> {
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit(event).await?;
        }
        Ok(())
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
    use async_trait::async_trait;
    use sqlx::SqlitePool;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use torii_core::{DefaultUserManager, error::EventError, events::EventHandler};
    use torii_storage_sqlite::SqliteStorage;

    async fn setup_storage() -> Result<Arc<SqliteStorage>, Error> {
        let _ = tracing_subscriber::fmt().try_init();

        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");

        let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
        user_storage.migrate().await?;

        Ok(user_storage)
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
    async fn test_create_user_and_login_with_unverified_email() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let plugin = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "password", None)
            .await?;
        assert_eq!(plugin.email, "test@example.com");

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .login_user_with_password("test@example.com", "password")
            .await;
        assert!(matches!(
            result,
            Err(Error::Auth(AuthError::EmailNotVerified))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_create_user_and_login_with_verified_email() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let plugin = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;
        assert_eq!(plugin.email, "test@example.com");

        let plugin = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .login_user_with_password("test@example.com", "password")
            .await?;
        assert_eq!(plugin.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let _ = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "password", None)
            .await?;

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "password", None)
            .await;

        assert!(matches!(
            result,
            Err(Error::Auth(AuthError::UserAlreadyExists))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_email_format() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("not-an-email", "password", None)
            .await;

        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidEmail))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_weak_password() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "123", None)
            .await;

        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::WeakPassword))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_password_login() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .login_user_with_password("test@example.com", "wrong-password")
            .await;

        assert!(matches!(
            result,
            Err(Error::Auth(AuthError::InvalidCredentials))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_user_login() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .login_user_with_password("nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::Auth(AuthError::UserNotFound))));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let result = PasswordPlugin::new(user_manager.clone(), storage.clone())
            .register_user_with_password("test@example.com'; DROP TABLE users;--", "password", None)
            .await;

        assert!(matches!(
            result,
            Err(Error::Validation(ValidationError::InvalidEmail))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_change_password() -> Result<(), Error> {
        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let plugin = PasswordPlugin::new(user_manager.clone(), storage.clone());

        // Create initial user
        let user = plugin
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;

        // Change password
        plugin
            .change_user_password(&user.id, "password", "new-password")
            .await?;

        // Verify can login with new password
        let result = plugin
            .login_user_with_password("test@example.com", "new-password")
            .await;
        assert!(result.is_ok());

        // Verify can't login with old password
        let result = plugin
            .login_user_with_password("test@example.com", "password")
            .await;
        assert!(matches!(
            result,
            Err(Error::Auth(AuthError::InvalidCredentials))
        ));

        Ok(())
    }

    #[tokio::test]
    async fn test_event_handler_emitting() -> Result<(), Error> {
        let _ = tracing_subscriber::fmt().try_init();

        let storage = setup_storage().await?;
        let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

        let event_bus = EventBus::new();
        let event_was_emitted = Arc::new(AtomicBool::new(false));
        let event_count = Arc::new(AtomicUsize::new(0));

        let handler = TestEventHandler {
            called: event_was_emitted.clone(),
            call_count: event_count.clone(),
        };
        event_bus.register(Arc::new(handler)).await;

        let plugin =
            PasswordPlugin::new(user_manager.clone(), storage.clone()).with_event_bus(event_bus);

        // Test user creation event
        let user = plugin
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;

        assert!(
            event_was_emitted.load(Ordering::SeqCst),
            "Expected event to be emitted on user creation"
        );
        assert_eq!(event_count.load(Ordering::SeqCst), 1);

        // Test password change event
        event_was_emitted.store(false, Ordering::SeqCst);
        plugin
            .change_user_password(&user.id, "password", "new-password")
            .await?;

        assert!(
            event_was_emitted.load(Ordering::SeqCst),
            "Expected event to be emitted on password change"
        );
        assert_eq!(event_count.load(Ordering::SeqCst), 2);

        Ok(())
    }

    struct TestEventHandler {
        called: Arc<AtomicBool>,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventHandler for TestEventHandler {
        async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
            self.called.store(true, Ordering::SeqCst);
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
}
