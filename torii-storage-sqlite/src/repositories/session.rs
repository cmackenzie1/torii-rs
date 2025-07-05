use async_trait::async_trait;
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
    token: String,
    user_id: String,
    user_agent: Option<String>,
    ip_address: Option<String>,
    created_at: i64,
    updated_at: i64,
    expires_at: i64,
}

impl From<SqliteSession> for Session {
    fn from(session: SqliteSession) -> Self {
        use chrono::DateTime;
        Session {
            token: SessionToken::new(&session.token),
            user_id: UserId::new(&session.user_id),
            user_agent: session.user_agent,
            ip_address: session.ip_address,
            created_at: DateTime::from_timestamp(session.created_at, 0).expect("Invalid timestamp"),
            updated_at: DateTime::from_timestamp(session.updated_at, 0).expect("Invalid timestamp"),
            expires_at: DateTime::from_timestamp(session.expires_at, 0).expect("Invalid timestamp"),
        }
    }
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    async fn create(&self, session: Session) -> Result<Session, Error> {
        let token_str = match &session.token {
            SessionToken::Opaque(t) => t,
            SessionToken::Jwt(t) => t,
        };

        let sqlite_session = sqlx::query_as::<_, SqliteSession>(
            r#"
            INSERT INTO sessions (token, user_id, user_agent, ip_address, created_at, updated_at, expires_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING *
            "#,
        )
        .bind(token_str)
        .bind(session.user_id.as_str())
        .bind(&session.user_agent)
        .bind(&session.ip_address)
        .bind(session.created_at.timestamp())
        .bind(session.updated_at.timestamp())
        .bind(session.expires_at.timestamp())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_session.into())
    }

    async fn find_by_token(&self, token: &SessionToken) -> Result<Option<Session>, Error> {
        let token_str = match token {
            SessionToken::Opaque(t) => t,
            SessionToken::Jwt(t) => t,
        };

        let sqlite_session =
            sqlx::query_as::<_, SqliteSession>("SELECT * FROM sessions WHERE token = ?1")
                .bind(token_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Storage(StorageError::Database(e.to_string())))?;

        Ok(sqlite_session.map(|s| s.into()))
    }

    async fn delete(&self, token: &SessionToken) -> Result<(), Error> {
        let token_str = match token {
            SessionToken::Opaque(t) => t,
            SessionToken::Jwt(t) => t,
        };

        sqlx::query("DELETE FROM sessions WHERE token = ?1")
            .bind(token_str)
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
}
