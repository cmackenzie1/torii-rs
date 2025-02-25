//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
use chrono::{DateTime, Utc};
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use torii_core::Plugin;
use torii_core::error::{AuthError, StorageError, ValidationError};
use torii_core::events::{Event, EventBus};
use torii_core::session::SessionId;
use torii_core::storage::{EmailPasswordStorage, Storage};
use torii_core::{
    Error, Session, User, UserId,
    storage::{NewUser, SessionStorage},
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
    S: SessionStorage,
{
    storage: Storage<U, S>,
    event_bus: Option<EventBus>,
}

impl<U, S> EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage,
{
    pub fn new(storage: Storage<U, S>) -> Self {
        Self {
            storage,
            event_bus: None,
        }
    }

    pub fn with_event_bus(mut self, event_bus: EventBus) -> Self {
        self.event_bus = Some(event_bus);
        self
    }
}

impl<U, S> Plugin for EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage,
{
    fn name(&self) -> String {
        "email_password".to_string()
    }
}

impl<U, S> EmailPasswordPlugin<U, S>
where
    U: EmailPasswordStorage,
    S: SessionStorage,
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

        if let Some(_user) = self
            .storage
            .user_storage()
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?
        {
            tracing::debug!(email = %email, "User already exists");
            return Err(Error::Auth(AuthError::UserAlreadyExists));
        }

        let new_user = NewUser::builder()
            .email(email.to_string())
            .email_verified_at(email_verified_at)
            .build()
            .unwrap();
        let user = self
            .storage
            .create_user(&new_user)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        let hash = generate_hash(password);
        self.storage
            .user_storage()
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
            .storage
            .user_storage()
            .get_user(user_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?
            .ok_or(Error::Auth(AuthError::UserNotFound))?;

        let stored_hash = self
            .storage
            .user_storage()
            .get_password_hash(user_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        if stored_hash.is_none() {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        verify_password(old_password, &stored_hash.unwrap())
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        let new_hash = generate_hash(new_password);
        self.storage
            .user_storage()
            .set_password_hash(user_id, &new_hash)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        // Delete all existing sessions for this user for security
        self.delete_sessions_for_user(user_id).await?;

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
    ) -> Result<(User, Session), Error> {
        let user_storage = self.storage.user_storage();

        let user = user_storage
            .get_user_by_email(email)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?
            .ok_or(Error::Auth(AuthError::UserNotFound))?;

        if !user.is_email_verified() {
            return Err(Error::Auth(AuthError::EmailNotVerified));
        }

        let hash = user_storage
            .get_password_hash(&user.id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        if hash.is_none() {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        verify_password(password, &hash.unwrap())
            .map_err(|_| Error::Auth(AuthError::InvalidCredentials))?;

        let session = self.create_session(&user.id).await?;

        Ok((user, session))
    }

    async fn emit_event(&self, event: &Event) -> Result<(), Error> {
        if let Some(event_bus) = &self.event_bus {
            event_bus.emit(event).await?;
        }
        Ok(())
    }

    async fn create_session(&self, user_id: &UserId) -> Result<Session, Error> {
        let session = self
            .storage
            .create_session(&Session::builder().user_id(user_id.clone()).build().unwrap())
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        self.emit_event(&Event::SessionCreated(user_id.clone(), session.clone()))
            .await?;

        Ok(session)
    }

    #[allow(unused)]
    async fn delete_session(&self, user_id: &UserId, session_id: &SessionId) -> Result<(), Error> {
        let session = self
            .storage
            .session_storage()
            .get_session(session_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?
            .ok_or(Error::Auth(AuthError::SessionNotFound))?;

        self.storage
            .session_storage()
            .delete_session(session_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        self.emit_event(&Event::SessionDeleted(user_id.clone(), session.id))
            .await?;

        Ok(())
    }

    async fn delete_sessions_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.storage
            .session_storage()
            .delete_sessions_for_user(user_id)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        self.emit_event(&Event::SessionsCleared(user_id.clone()))
            .await?;

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
    use torii_core::{PluginManager, error::EventError, events::EventHandler};
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
        manager.register_plugin(EmailPasswordPlugin::new(storage));

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
    async fn test_create_user_and_login_with_unverified_email() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .register_user_with_password("test@example.com", "password", None)
            .await?;
        assert_eq!(user.email, "test@example.com");

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
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
        let (manager,) = setup_plugin().await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;
        assert_eq!(user.email, "test@example.com");

        let (user, session) = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .login_user_with_password("test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");
        assert_eq!(session.user_id, user.id);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
            .register_user_with_password("test@example.com", "password", None)
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .unwrap()
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
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
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
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
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
        let (manager,) = setup_plugin().await?;

        manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
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
        let (manager,) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .login_user_with_password("nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::Auth(AuthError::UserNotFound))));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let (manager,) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist")
            .register_user_with_password("test@example.com'; DROP TABLE users;--", "password", None)
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
        let user = plugin
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;

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
            .change_user_password(&user.id, "password", "new-password")
            .await?;

        // Verify old session was deleted
        let deleted_session = manager.storage().get_session(&session.id).await;
        assert!(deleted_session.is_err());

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

        // Create in-memory SQLite database and storage
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");
        let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
        let session_storage = Arc::new(SqliteStorage::new(pool));

        // Initialize database schema
        user_storage.migrate().await.unwrap();
        session_storage.migrate().await.unwrap();

        // Create plugin manager and event bus
        let storage = Storage::new(user_storage.clone(), session_storage.clone());
        let mut manager = PluginManager::new(user_storage, session_storage);
        let event_bus = EventBus::new();

        // Register plugin with event bus
        let plugin = EmailPasswordPlugin::new(storage).with_event_bus(event_bus.clone());
        manager.register_plugin(plugin);

        // Create test event handler that tracks when events are emitted
        let event_was_emitted = Arc::new(AtomicBool::new(false));
        let event_count = Arc::new(AtomicUsize::new(0));
        let handler = TestEventHandler {
            called: event_was_emitted.clone(),
            call_count: event_count.clone(),
        };
        event_bus.register(Arc::new(handler)).await;

        let plugin = manager
            .get_plugin::<EmailPasswordPlugin<SqliteStorage, SqliteStorage>>("email_password")
            .expect("Plugin should exist");

        // Test 1: Creating a user should emit an event
        let user = plugin
            .register_user_with_password("test@example.com", "password", Some(Utc::now()))
            .await?;
        assert!(
            event_was_emitted.load(Ordering::SeqCst),
            "No event emitted when creating user"
        );
        assert_eq!(event_count.load(Ordering::SeqCst), 1);

        // Test 2: Changing password should emit 2 events, one for the user update and one for the session deletion
        event_was_emitted.store(false, Ordering::SeqCst);
        plugin
            .change_user_password(&user.id, "password", "new-password")
            .await?;
        assert!(
            event_was_emitted.load(Ordering::SeqCst),
            "No event emitted when changing password"
        );
        assert_eq!(event_count.load(Ordering::SeqCst), 3);

        // Test 3: Logging in should emit 1 event
        event_was_emitted.store(false, Ordering::SeqCst);
        plugin
            .login_user_with_password("test@example.com", "new-password")
            .await?;
        assert!(
            event_was_emitted.load(Ordering::SeqCst),
            "No event emitted when logging in"
        );
        assert_eq!(event_count.load(Ordering::SeqCst), 4);

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
