//! This plugin provides email and password authentication for Torii.
//!
//! Username is set to the provided email address.
//!
//! Password is hashed using the `password_auth` crate using argon2.
mod migrations;

use std::any::TypeId;

use async_trait::async_trait;
use migrations::AddPasswordHashColumn;
use password_auth::{generate_hash, verify_password};
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
    fn id(&self) -> TypeId {
        TypeId::of::<EmailPasswordPlugin>()
    }

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
            "#,
        )
        .bind(email)
        .fetch_one(pool)
        .await?;

        let stored_hash: String = row.get("password_hash");
        if verify_password(password, &stored_hash).is_err() {
            return Err(Error::InvalidCredentials);
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;
    use torii_core::PluginManager;

    #[tokio::test]
    async fn test_plugin_setup() -> Result<(), Error> {
        let pool = SqlitePool::connect("sqlite::memory:")
            .await
            .expect("Failed to create pool");

        let manager = PluginManager::new();
        manager.register(EmailPasswordPlugin);

        // Initialize and run migrations
        manager.setup(&pool).await?;
        manager.migrate(&pool).await?;

        let count = sqlx::query("SELECT count(*) FROM users")
            .fetch_one(&pool)
            .await?;
        assert_eq!(count.get::<i64, _>(0), 0);

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
}
