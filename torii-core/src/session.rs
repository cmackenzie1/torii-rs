use crate::user::UserId;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Hash, sqlx::Type)]
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

pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(session.id.to_string(), session.id.0.to_string());
    }
}
