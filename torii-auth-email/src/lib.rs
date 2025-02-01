//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
mod migrations;

use async_trait::async_trait;
use migrations::AddPasswordHashColumn;
use password_auth::{generate_hash, verify_password};
use regex::Regex;
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;
use sqlx::Row;
use torii_core::migration::PluginMigration;
use torii_core::{Error, Plugin, User, UserId};
pub struct EmailPasswordPlugin;

impl Default for EmailPasswordPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl EmailPasswordPlugin {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Plugin for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email_password"
    }

    async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
        Ok(())
    }

    fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
        vec![Box::new(AddPasswordHashColumn)]
    }
}

impl EmailPasswordPlugin {
    pub async fn create_user(
        &self,
        pool: &Pool<Sqlite>,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        let user_id = UserId::new_random();
        let password_hash = generate_hash(password);

        if !is_valid_email(email) {
            return Err(Error::InvalidEmailFormat);
        }
        if !is_valid_password(password) {
            return Err(Error::WeakPassword);
        }

        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)
            "#,
        )
        .bind(&user_id)
        .bind(email)
        .bind(password_hash)
        .execute(pool)
        .await?;

        let user = sqlx::query(
            r#"
            SELECT id, email, name, email_verified_at, created_at, updated_at
            FROM users
            WHERE id = ?
            "#,
        )
        .bind(&user_id)
        .fetch_one(pool)
        .await?;

        tracing::info!(
            user.id = %user.get::<String, _>("id"),
            user.email = %user.get::<String, _>("email"),
            user.name = %user.get::<String, _>("name"),
            "Created user",
        );

        Ok(User {
            id: user.get("id"),
            name: user.get("name"),
            email: user.get("email"),
            email_verified_at: user.get("email_verified_at"),
            created_at: user.get("created_at"),
            updated_at: user.get("updated_at"),
        })
    }

    pub async fn login_user(
        &self,
        pool: &Pool<Sqlite>,
        email: &str,
        password: &str,
    ) -> Result<User, Error> {
        let row = sqlx::query(
            r#"
            SELECT id, name, email, email_verified_at, password_hash, created_at, updated_at
            FROM users
            WHERE email = ?
            LIMIT 1
            "#,
        )
        .bind(email)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => Error::UserNotFound,
            _ => e.into(),
        })?;

        let stored_hash: String = row.get("password_hash");

        if verify_password(password, &stored_hash).is_err() {
            tracing::error!(email = email, "Invalid credentials");
            return Err(Error::InvalidCredentials);
        }

        tracing::info!(
            row.id = %row.get::<String, _>("id"),
            row.email = %row.get::<String, _>("email"),
            row.name = %row.get::<String, _>("name"),
            "Logged in user",
        );

        Ok(User {
            id: row.get("id"),
            name: row.get("name"),
            email: row.get("email"),
            email_verified_at: row.get("email_verified_at"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
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
    use torii_core::PluginManager;

    async fn setup_plugin() -> Result<(PluginManager, Pool<Sqlite>), Error> {
        let _ = tracing_subscriber::fmt().try_init(); // don't panic if this fails

        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");

        let mut manager = PluginManager::new();
        manager.register(EmailPasswordPlugin);
        manager.setup(&pool).await?;
        manager.migrate(&pool).await?;

        Ok((manager, pool))
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
    async fn test_plugin_setup() -> Result<(), Error> {
        let (_, pool) = setup_plugin().await?;

        let count = sqlx::query("SELECT count(*) FROM users")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count.get::<i64, _>(0), 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_create_user_and_login() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&pool, "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        let user = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .login_user(&pool, "test@example.com", "password")
            .await?;
        assert_eq!(user.email, "test@example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_create_duplicate_user() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&pool, "test@example.com", "password")
            .await?;

        let user = manager
            .get_plugin::<EmailPasswordPlugin>()
            .unwrap()
            .create_user(&pool, "test@example.com", "password")
            .await;

        assert!(user.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_invalid_email_format() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&pool, "not-an-email", "password")
            .await;

        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_weak_password() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&pool, "test@example.com", "123")
            .await;

        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn test_incorrect_password_login() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&pool, "test@example.com", "password")
            .await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .login_user(&pool, "test@example.com", "wrong-password")
            .await;

        assert!(matches!(result, Err(Error::InvalidCredentials)));

        Ok(())
    }

    #[tokio::test]
    async fn test_nonexistent_user_login() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let result = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .login_user(&pool, "nonexistent@example.com", "password")
            .await;

        assert!(matches!(result, Err(Error::UserNotFound)));

        Ok(())
    }

    #[tokio::test]
    async fn test_sql_injection_attempt() -> Result<(), Error> {
        let (manager, pool) = setup_plugin().await?;

        let _ = manager
            .get_plugin::<EmailPasswordPlugin>()
            .expect("Plugin should exist")
            .create_user(&pool, "test@example.com'; DROP TABLE users;--", "password")
            .await
            .expect_err("Should fail validation");

        // Verify table still exists and no user was created
        let count = sqlx::query("SELECT count(*) FROM users")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count.get::<i64, _>(0), 0);

        Ok(())
    }
}
