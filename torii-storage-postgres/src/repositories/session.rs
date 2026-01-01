//! PostgreSQL implementation of the session repository.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use torii_core::{
    Error, Session, UserId, error::StorageError, repositories::SessionRepository,
    session::SessionToken,
};

/// PostgreSQL repository for session data.
pub struct PostgresSessionRepository {
    pool: PgPool,
}

impl PostgresSessionRepository {
    /// Create a new PostgreSQL session repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct PgSession {
    token: String, // This stores the hash, not plaintext
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

#[async_trait]
impl SessionRepository for PostgresSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        // Store the hash, not the plaintext token
        sqlx::query(
            r#"
            INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&session.token_hash) // Store hash, not plaintext
        .bind(session.user_id.as_str())
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .bind(session.created_at)
        .bind(session.updated_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create session");
            Error::Storage(StorageError::Database("Failed to create session".to_string()))
        })?;

        // Return the original session (caller already has plaintext token)
        Ok(session)
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        // Compute hash for lookup
        let token_hash = token.token_hash();

        let pg_session = sqlx::query_as::<_, PgSession>(
            r#"
            SELECT token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE token = $1
            "#,
        )
        .bind(&token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find session by token");
            Error::Storage(StorageError::Database(
                "Failed to find session by token".to_string(),
            ))
        })?;

        match pg_session {
            Some(s) => {
                // Verify using constant-time comparison
                if token.verify_hash(&s.token) {
                    Ok(Some(Session {
                        token: token.clone(),
                        token_hash: s.token,
                        user_id: UserId::new(&s.user_id),
                        user_agent: s.user_agent,
                        ip_address: s.ip_address,
                        created_at: s.created_at,
                        updated_at: s.updated_at,
                        expires_at: s.expires_at,
                    }))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        let token_hash = token.token_hash();

        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete session");
                Error::Storage(StorageError::Database(
                    "Failed to delete session".to_string(),
                ))
            })?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete sessions for user");
                Error::Storage(StorageError::Database(
                    "Failed to delete sessions for user".to_string(),
                ))
            })?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
            .bind(Utc::now())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to cleanup expired sessions");
                Error::Storage(StorageError::Database(
                    "Failed to cleanup expired sessions".to_string(),
                ))
            })?;

        Ok(())
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Session>, Error> {
        let pg_sessions = sqlx::query_as::<_, PgSession>(
            r#"
            SELECT token, user_id, user_agent, ip_address, created_at, updated_at, expires_at
            FROM sessions
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find sessions by user_id");
            Error::Storage(StorageError::Database(
                "Failed to find sessions by user_id".to_string(),
            ))
        })?;

        Ok(pg_sessions
            .into_iter()
            .map(|s| Session {
                // Note: We don't have the plaintext token, only the hash
                // Create an empty token - callers should not use this for auth
                token: SessionToken::empty(),
                token_hash: s.token,
                user_id: UserId::new(&s.user_id),
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                created_at: s.created_at,
                updated_at: s.updated_at,
                expires_at: s.expires_at,
            })
            .collect())
    }

    async fn refresh(&self, token: &SessionToken, duration: Duration) -> Result<Session, Error> {
        let token_hash = token.token_hash();
        let now = Utc::now();
        let new_expires_at = now + duration;

        sqlx::query("UPDATE sessions SET expires_at = $1, updated_at = $2 WHERE token = $3")
            .bind(new_expires_at)
            .bind(now)
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to refresh session");
                Error::Storage(StorageError::Database(
                    "Failed to refresh session".to_string(),
                ))
            })?;

        // Fetch and return the updated session
        self.find_by_token(token)
            .await?
            .ok_or_else(|| Error::Storage(StorageError::Database("Session not found".to_string())))
    }
}
