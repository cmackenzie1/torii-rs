mod magic_link;
mod migrations;
mod oauth;
mod passkey;
mod password;
mod session;

use async_trait::async_trait;
use chrono::DateTime;
use chrono::Utc;
use migrations::CreateIndexes;
use migrations::CreateMagicLinksTable;
use migrations::CreateOAuthAccountsTable;
use migrations::CreatePasskeyChallengesTable;
use migrations::CreatePasskeysTable;
use migrations::CreateSessionsTable;
use migrations::CreateUsersTable;
use migrations::PostgresMigrationManager;
use sqlx::PgPool;
use torii_core::error::StorageError;
use torii_core::{
    User, UserId,
    storage::{NewUser, UserStorage},
};
use torii_migration::Migration;
use torii_migration::MigrationManager;

#[derive(Debug)]
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), StorageError> {
        let manager = PostgresMigrationManager::new(self.pool.clone());
        manager.initialize().await.map_err(|e| {
            tracing::error!(error = %e, "Failed to initialize migrations");
            StorageError::Migration("Failed to initialize migrations".to_string())
        })?;

        let migrations: Vec<Box<dyn Migration<_>>> = vec![
            Box::new(CreateUsersTable),
            Box::new(CreateSessionsTable),
            Box::new(CreateOAuthAccountsTable),
            Box::new(CreatePasskeysTable),
            Box::new(CreatePasskeyChallengesTable),
            Box::new(CreateIndexes),
            Box::new(CreateMagicLinksTable),
        ];
        manager.up(&migrations).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to run migrations");
            StorageError::Migration("Failed to run migrations".to_string())
        })?;

        Ok(())
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresUser {
    id: String,
    email: String,
    name: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<PostgresUser> for User {
    fn from(user: PostgresUser) -> Self {
        User::builder()
            .id(UserId::new(&user.id))
            .email(user.email)
            .name(user.name)
            .email_verified_at(user.email_verified_at)
            .created_at(user.created_at)
            .updated_at(user.updated_at)
            .build()
            .unwrap()
    }
}

impl From<User> for PostgresUser {
    fn from(user: User) -> Self {
        PostgresUser {
            id: user.id.into_inner(),
            email: user.email,
            name: user.name,
            email_verified_at: user.email_verified_at,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

#[async_trait]
impl UserStorage for PostgresStorage {
    type Error = torii_core::Error;

    async fn create_user(&self, user: &NewUser) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            INSERT INTO users (id, email) 
            VALUES ($1::uuid, $2) 
            RETURNING id::text, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(user.id.as_str())
        .bind(&user.email)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create user");
            StorageError::Database("Failed to create user".to_string())
        })?;

        Ok(user.into())
    }

    async fn get_user(&self, id: &UserId) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id::text, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE id::text = $1
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user");
            StorageError::Database("Failed to get user".to_string())
        })?;

        match user {
            Some(user) => Ok(Some(user.into())),
            None => Ok(None),
        }
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            SELECT id::text, email, name, email_verified_at, created_at, updated_at 
            FROM users 
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get user by email");
            StorageError::Database("Failed to get user by email".to_string())
        })?;

        match user {
            Some(user) => Ok(Some(user.into())),
            None => Ok(None),
        }
    }

    async fn get_or_create_user_by_email(&self, email: &str) -> Result<User, Self::Error> {
        let user = self.get_user_by_email(email).await?;
        if let Some(user) = user {
            return Ok(user);
        }

        let user = self
            .create_user(
                &NewUser::builder()
                    .id(UserId::new_random())
                    .email(email.to_string())
                    .build()
                    .unwrap(),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to get or create user by email");
                StorageError::Database("Failed to get or create user by email".to_string())
            })?;

        Ok(user)
    }

    async fn update_user(&self, user: &User) -> Result<User, Self::Error> {
        let user = sqlx::query_as::<_, PostgresUser>(
            r#"
            UPDATE users 
            SET email = $1, name = $2, email_verified_at = $3, updated_at = $4 
            WHERE id::text = $5
            RETURNING id::text, email, name, email_verified_at, created_at, updated_at
            "#,
        )
        .bind(&user.email)
        .bind(&user.name)
        .bind(user.email_verified_at)
        .bind(user.updated_at)
        .bind(user.id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update user");
            StorageError::Database("Failed to update user".to_string())
        })?;

        Ok(user.into())
    }

    async fn delete_user(&self, id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("DELETE FROM users WHERE id::text = $1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete user");
                StorageError::Database("Failed to delete user".to_string())
            })?;

        Ok(())
    }

    async fn set_user_email_verified(&self, user_id: &UserId) -> Result<(), Self::Error> {
        sqlx::query("UPDATE users SET email_verified_at = $1 WHERE id::text = $2")
            .bind(Utc::now())
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to set user email verified");
                StorageError::Database("Failed to set user email verified".to_string())
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use sqlx::types::chrono::Utc;
    use std::time::Duration;
    use torii_core::session::SessionId;
    use torii_core::{Session, SessionStorage};

    pub(crate) async fn setup_test_db() -> PostgresStorage {
        // TODO: this function is leaking postgres databases after the test is done.
        // We should find a way to clean up the database after the test is done.

        let _ = tracing_subscriber::fmt().try_init();

        let pool = PgPool::connect("postgres://postgres:postgres@localhost:5432/postgres")
            .await
            .expect("Failed to create pool");

        let db_name = format!("torii_test_{}", rand::rng().random_range(1..i64::MAX));

        // Drop the database if it exists
        sqlx::query(format!("DROP DATABASE IF EXISTS {}", db_name).as_str())
            .execute(&pool)
            .await
            .expect("Failed to drop database");

        // Create a new database for the test
        sqlx::query(format!("CREATE DATABASE {}", db_name).as_str())
            .execute(&pool)
            .await
            .expect("Failed to create database");

        let pool = PgPool::connect(
            format!("postgres://postgres:postgres@localhost:5432/{}", db_name).as_str(),
        )
        .await
        .expect("Failed to create pool");

        let storage = PostgresStorage::new(pool);
        storage.migrate().await.expect("Failed to run migrations");
        storage
    }

    pub(crate) async fn create_test_user(
        storage: &PostgresStorage,
        id: &UserId,
    ) -> Result<User, torii_core::Error> {
        storage
            .create_user(
                &NewUser::builder()
                    .id(id.clone())
                    .email(format!("test{}@example.com", id))
                    .build()
                    .expect("Failed to build user"),
            )
            .await
    }

    pub(crate) async fn create_test_session(
        storage: &PostgresStorage,
        session_id: &SessionId,
        user_id: &UserId,
        expires_in: Duration,
    ) -> Result<Session, torii_core::Error> {
        let now = Utc::now();
        storage
            .create_session(
                &Session::builder()
                    .id(session_id.clone())
                    .user_id(user_id.clone())
                    .user_agent(Some("test".to_string()))
                    .ip_address(Some("127.0.0.1".to_string()))
                    .created_at(now)
                    .updated_at(now)
                    .expires_at(now + expires_in)
                    .build()
                    .expect("Failed to build session"),
            )
            .await
    }
}
