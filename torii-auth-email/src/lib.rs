mod migrations;

use async_trait::async_trait;
use password_auth::{generate_hash, verify_password};
use sqlx::pool::Pool;
use sqlx::sqlite::Sqlite;
use sqlx::Row;
use torii_core::migration::PluginMigration;
use torii_core::plugin::CreateUserParams;
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

    async fn create_user(
        &self,
        pool: &Pool<Sqlite>,
        params: &CreateUserParams,
    ) -> Result<(), Error> {
        let (username, password) = match params {
            CreateUserParams::Password { username, password } => (username, password),
            _ => return Err(Error::Auth("Unsupported create user params".into())),
        };

        let password_hash = generate_hash(password);

        sqlx::query(
            r#"
            INSERT INTO torii_users (username, password_hash) VALUES (?, ?)
            "#,
        )
        .bind(username)
        .bind(password_hash)
        .execute(pool)
        .await?;
        Ok(())
    }

    async fn authenticate(&self, pool: &Pool<Sqlite>, creds: &Credentials) -> Result<User, Error> {
        let password = creds
            .password
            .as_ref()
            .ok_or_else(|| Error::Auth("Password required".into()))?;

        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash
            FROM torii_users
            WHERE username = ?
            "#,
        )
        .bind(&creds.username)
        .fetch_one(pool)
        .await?;

        let stored_hash: String = row.get("password_hash");
        if verify_password(password, &stored_hash).is_err() {
            return Err(Error::Auth("Invalid credentials".into()));
        }

        Ok(User {
            id: row.get(0),
            username: row.get(1),
        })
    }

    fn migrations(&self) -> Vec<Box<dyn PluginMigration>> {
        vec![Box::new(migrations::AddPasswordColumn)]
    }
}
