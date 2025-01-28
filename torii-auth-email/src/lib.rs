mod migrations;

use async_trait::async_trait;
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;
use sqlx::Row;
use torii_core::migration::PluginMigration;
use torii_core::{AuthPlugin, Credentials, Error, User};

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
impl AuthPlugin for EmailPasswordPlugin {
    fn name(&self) -> &'static str {
        "email_password"
    }

    async fn setup(&self, _pool: &Pool<Sqlite>) -> Result<(), Error> {
        Ok(())
    }

    async fn authenticate(&self, pool: &Pool<Sqlite>, creds: &Credentials) -> Result<User, Error> {
        let password = creds
            .password
            .as_ref()
            .ok_or_else(|| Error::Auth("Password required".into()))?;

        let row = sqlx::query(
            r#"
            SELECT id, username
            FROM users
            WHERE username = ? AND password_hash = ?
            "#,
        )
        .bind(&creds.username)
        .bind(password)
        .fetch_one(pool)
        .await?;

        Ok(User {
            id: row.get(0),
            username: row.get(1),
        })
    }

    fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
        vec![Box::new(migrations::CreateUsersTable)]
    }
}
