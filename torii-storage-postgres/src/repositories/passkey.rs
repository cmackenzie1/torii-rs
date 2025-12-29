//! PostgreSQL implementation of the passkey repository.

use async_trait::async_trait;
use base64::prelude::*;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use torii_core::{
    Error, UserId,
    error::StorageError,
    repositories::{PasskeyCredential, PasskeyRepository},
};

/// PostgreSQL repository for passkey data.
pub struct PostgresPasskeyRepository {
    pool: PgPool,
}

impl PostgresPasskeyRepository {
    /// Create a new PostgreSQL passkey repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, sqlx::FromRow)]
struct PostgresPasskey {
    #[allow(dead_code)]
    id: i64,
    credential_id: String,
    user_id: String,
    public_key: String,
    name: Option<String>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl PasskeyRepository for PostgresPasskeyRepository {
    async fn add_credential(
        &self,
        user_id: &UserId,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        name: Option<String>,
    ) -> Result<PasskeyCredential, Error> {
        let credential_id_b64 = BASE64_STANDARD.encode(&credential_id);
        let public_key_b64 = BASE64_STANDARD.encode(&public_key);
        let now = Utc::now();

        let passkey = sqlx::query_as::<_, PostgresPasskey>(
            r#"
            INSERT INTO passkeys (credential_id, user_id, public_key, name, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, credential_id, user_id, public_key, name, last_used_at, created_at, updated_at
            "#,
        )
        .bind(&credential_id_b64)
        .bind(user_id.as_str())
        .bind(&public_key_b64)
        .bind(&name)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to add passkey credential");
            Error::Storage(StorageError::Database(
                "Failed to add passkey credential".to_string(),
            ))
        })?;

        Ok(PasskeyCredential {
            user_id: user_id.clone(),
            credential_id,
            public_key,
            name,
            created_at: passkey.created_at,
            last_used_at: passkey.last_used_at,
        })
    }

    async fn get_credentials_for_user(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<PasskeyCredential>, Error> {
        let passkeys = sqlx::query_as::<_, PostgresPasskey>(
            r#"
            SELECT id, credential_id, user_id, public_key, name, last_used_at, created_at, updated_at
            FROM passkeys
            WHERE user_id = $1
            "#,
        )
        .bind(user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get passkey credentials for user");
            Error::Storage(StorageError::Database(
                "Failed to get passkey credentials for user".to_string(),
            ))
        })?;

        let mut credentials = Vec::new();
        for p in passkeys {
            let credential_id = BASE64_STANDARD.decode(&p.credential_id).map_err(|e| {
                tracing::error!(error = %e, "Failed to decode credential_id");
                Error::Storage(StorageError::Database(
                    "Failed to decode credential_id".to_string(),
                ))
            })?;

            let public_key = BASE64_STANDARD.decode(&p.public_key).map_err(|e| {
                tracing::error!(error = %e, "Failed to decode public_key");
                Error::Storage(StorageError::Database(
                    "Failed to decode public_key".to_string(),
                ))
            })?;

            credentials.push(PasskeyCredential {
                user_id: UserId::new(&p.user_id),
                credential_id,
                public_key,
                name: p.name,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            });
        }

        Ok(credentials)
    }

    async fn get_credential(
        &self,
        credential_id: &[u8],
    ) -> Result<Option<PasskeyCredential>, Error> {
        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);

        let passkey = sqlx::query_as::<_, PostgresPasskey>(
            r#"
            SELECT id, credential_id, user_id, public_key, name, last_used_at, created_at, updated_at
            FROM passkeys
            WHERE credential_id = $1
            "#,
        )
        .bind(&credential_id_b64)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get passkey credential");
            Error::Storage(StorageError::Database(
                "Failed to get passkey credential".to_string(),
            ))
        })?;

        if let Some(p) = passkey {
            let public_key = BASE64_STANDARD.decode(&p.public_key).map_err(|e| {
                tracing::error!(error = %e, "Failed to decode public_key");
                Error::Storage(StorageError::Database(
                    "Failed to decode public_key".to_string(),
                ))
            })?;

            Ok(Some(PasskeyCredential {
                user_id: UserId::new(&p.user_id),
                credential_id: credential_id.to_vec(),
                public_key,
                name: p.name,
                created_at: p.created_at,
                last_used_at: p.last_used_at,
            }))
        } else {
            Ok(None)
        }
    }

    async fn update_last_used(&self, credential_id: &[u8]) -> Result<(), Error> {
        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE passkeys SET last_used_at = $1, updated_at = $2
            WHERE credential_id = $3
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(&credential_id_b64)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update passkey last_used_at");
            Error::Storage(StorageError::Database(
                "Failed to update passkey last_used_at".to_string(),
            ))
        })?;

        Ok(())
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<(), Error> {
        let credential_id_b64 = BASE64_STANDARD.encode(credential_id);

        sqlx::query("DELETE FROM passkeys WHERE credential_id = $1")
            .bind(&credential_id_b64)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete passkey credential");
                Error::Storage(StorageError::Database(
                    "Failed to delete passkey credential".to_string(),
                ))
            })?;

        Ok(())
    }

    async fn delete_all_for_user(&self, user_id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM passkeys WHERE user_id = $1")
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete all passkeys for user");
                Error::Storage(StorageError::Database(
                    "Failed to delete all passkeys for user".to_string(),
                ))
            })?;

        Ok(())
    }
}

/// Internal helper methods for challenge storage
impl PostgresPasskeyRepository {
    /// Store a passkey challenge.
    pub async fn set_challenge(
        &self,
        challenge_id: &str,
        challenge: &str,
        expires_in: chrono::Duration,
    ) -> Result<(), Error> {
        let now = Utc::now();
        let expires_at = now + expires_in;

        sqlx::query(
            r#"
            INSERT INTO passkey_challenges (challenge_id, challenge, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (challenge_id) DO UPDATE SET challenge = $2, expires_at = $3, updated_at = $5
            "#,
        )
        .bind(challenge_id)
        .bind(challenge)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to set passkey challenge");
            Error::Storage(StorageError::Database(
                "Failed to set passkey challenge".to_string(),
            ))
        })?;

        Ok(())
    }

    /// Get a passkey challenge.
    pub async fn get_challenge(&self, challenge_id: &str) -> Result<Option<String>, Error> {
        let now = Utc::now();
        let challenge: Option<String> = sqlx::query_scalar(
            r#"
            SELECT challenge FROM passkey_challenges
            WHERE challenge_id = $1 AND expires_at > $2
            "#,
        )
        .bind(challenge_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to get passkey challenge");
            Error::Storage(StorageError::Database(
                "Failed to get passkey challenge".to_string(),
            ))
        })?;

        Ok(challenge)
    }
}
