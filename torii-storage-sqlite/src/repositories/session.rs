use async_trait::async_trait;
use chrono::Duration;
use sqlx::SqlitePool;
use torii_core::{
    Error, Session, UserId, error::StorageError, repositories::SessionRepository,
    session::SessionToken,
};

pub struct SqliteSessionRepository {
    pool: SqlitePool,
}

impl SqliteSessionRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SqliteSession {
    token: String, // This stores the hash, not plaintext
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        // Store the hash, not the plaintext token
        sqlx::query(
            r#"
            INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(&session.token_hash) // Store hash, not plaintext
        .bind(session.user_id.as_str())
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .bind(session.created_at.timestamp())
        .bind(session.updated_at.timestamp())
        .bind(session.expires_at.timestamp())
        .execute(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        // Return the original session (caller already has plaintext token)
        Ok(session)
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        // Compute hash for lookup
        let token_hash = token.token_hash();

        let sqlite_session =
            sqlx::query_as::<_, SqliteSession>("SELECT * FROM sessions WHERE token = ?1")
                .bind(&token_hash)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        match sqlite_session {
            Some(s) => {
                // Verify using constant-time comparison
                if token.verify_hash(&s.token) {
                    use chrono::DateTime;
                    Ok(Some(Session {
                        token: token.clone(),
                        token_hash: s.token,
                        user_id: UserId::new(&s.user_id),
                        user_agent: s.user_agent,
                        ip_address: s.ip_address,
                        created_at: DateTime::from_timestamp(s.created_at, 0)
                            .expect("Invalid timestamp"),
                        updated_at: DateTime::from_timestamp(s.updated_at, 0)
                            .expect("Invalid timestamp"),
                        expires_at: DateTime::from_timestamp(s.expires_at, 0)
                            .expect("Invalid timestamp"),
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

        sqlx::query("DELETE FROM sessions WHERE token = ?1")
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: &UserId) -> Result<(), Error> {
        sqlx::query("DELETE FROM sessions WHERE user_id = ?1")
            .bind(user_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<(), Error> {
        let now = chrono::Utc::now().timestamp();

        sqlx::query("DELETE FROM sessions WHERE expires_at < ?1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(())
    }

    async fn find_by_user_id(&self, user_id: &UserId) -> Result<Vec<Session>, Error> {
        let sqlite_sessions = sqlx::query_as::<_, SqliteSession>(
            "SELECT * FROM sessions WHERE user_id = ?1 ORDER BY created_at DESC",
        )
        .bind(user_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        use chrono::DateTime;
        Ok(sqlite_sessions
            .into_iter()
            .map(|s| Session {
                // Note: We don't have the plaintext token, only the hash
                // Create an empty token - callers should not use this for auth
                token: SessionToken::empty(),
                token_hash: s.token,
                user_id: UserId::new(&s.user_id),
                user_agent: s.user_agent,
                ip_address: s.ip_address,
                created_at: DateTime::from_timestamp(s.created_at, 0).expect("Invalid timestamp"),
                updated_at: DateTime::from_timestamp(s.updated_at, 0).expect("Invalid timestamp"),
                expires_at: DateTime::from_timestamp(s.expires_at, 0).expect("Invalid timestamp"),
            })
            .collect())
    }

    async fn refresh(&self, token: &SessionToken, duration: Duration) -> Result<Session, Error> {
        let token_hash = token.token_hash();
        let now = chrono::Utc::now();
        let new_expires_at = now + duration;

        sqlx::query("UPDATE sessions SET expires_at = ?1, updated_at = ?2 WHERE token = ?3")
            .bind(new_expires_at.timestamp())
            .bind(now.timestamp())
            .bind(&token_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        // Fetch and return the updated session
        self.find_by_token(token)
            .await?
            .ok_or_else(|| Error::Storage(StorageError::Database("Session not found".to_string())))
    }
}
