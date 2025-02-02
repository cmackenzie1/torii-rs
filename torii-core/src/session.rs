//! Session management
//!
//! This module contains the core session struct and related functionality.
//!
//! Sessions are used to track user sessions and are used to authenticate users. The core session struct is defined as follows:
//!
//! | Field        | Type             | Description                                            |
//! | ------------ | ---------------- | ------------------------------------------------------ |
//! | `id`         | `String`         | The unique identifier for the session.                 |
//! | `user_id`    | `String`         | The unique identifier for the user.                    |
//! | `user_agent` | `Option<String>` | The user agent of the client that created the session. |
//! | `ip_address` | `Option<String>` | The IP address of the client that created the session. |
//! | `created_at` | `DateTime`       | The timestamp when the session was created.            |
//! | `updated_at` | `DateTime`       | The timestamp when the session was last updated.       |
//! | `expires_at` | `DateTime`       | The timestamp when the session will expire.            |
use crate::user::UserId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn new_random() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The unique identifier for the session.
    pub id: SessionId,

    /// The unique identifier for the user.
    pub user_id: UserId,

    /// The user agent of the client that created the session.
    pub user_agent: Option<String>,

    /// The IP address of the client that created the session.
    pub ip_address: Option<String>,

    /// The timestamp when the session was created.
    pub created_at: DateTime<Utc>,

    /// The timestamp when the session was last updated.
    pub updated_at: DateTime<Utc>,

    /// The timestamp when the session will expire.
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn test_session_id() {
        let id = SessionId::new_random();
        assert_eq!(id.to_string(), id.0.to_string());
    }

    #[test]
    fn test_session() {
        let session = Session {
            id: SessionId::new_random(),
            user_id: UserId::new_random(),
            user_agent: None,
            ip_address: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(30),
        };

        assert_eq!(session.id.to_string(), session.id.0.to_string());
    }
}
