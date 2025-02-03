//! User management and authentication
//!
//! This module contains the core user struct and related functionality.
//!
//! Users are the core of the authentication system. They are responsible for storing user information and are used to identify users in the system. The core user struct is defined as follows:
//!
//! | Field               | Type               | Description                                       |
//! | ------------------- | ------------------ | ------------------------------------------------- |
//! | `id`                | `String`           | The unique identifier for the user.               |
//! | `name`              | `String`           | The name of the user.                             |
//! | `email`             | `String`           | The email of the user.                            |
//! | `email_verified_at` | `Option<DateTime>` | The timestamp when the user's email was verified. |
//! | `created_at`        | `DateTime`         | The timestamp when the user was created.          |
//! | `updated_at`        | `DateTime`         | The timestamp when the user was last updated.     |
use chrono::{DateTime, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A unique, stable identifier for a specific user
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize, Hash)]
#[sqlx(transparent)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: &str) -> Self {
        UserId(id.to_string())
    }

    pub fn new_random() -> Self {
        UserId(Uuid::new_v4().to_string())
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new_random()
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for UserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Representation of a user in Torii. This is the user object returned by all authentication plugins.
///
/// Many of these fields are optional, as they may not be available from the authentication provider,
/// or may not be known at the time of authentication.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, Builder)]
pub struct User {
    // The unique identifier for the user.
    #[builder(default = "UserId::new_random()")]
    pub id: UserId,

    // The name of the user.
    pub name: String,

    // The email of the user.
    pub email: String,

    // The email verified at timestamp. If the user has not verified their email, this will be None.
    #[builder(default = "None")]
    pub email_verified_at: Option<DateTime<Utc>>,

    // The created at timestamp.
    #[builder(default = "chrono::Utc::now()")]
    pub created_at: DateTime<Utc>,

    // The updated at timestamp.
    #[builder(default = "chrono::Utc::now()")]
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        let user_id = UserId::new("test");
        assert_eq!(user_id.as_ref(), "test");

        let user_id_from_str = UserId::from(user_id.as_ref());
        assert_eq!(user_id_from_str, user_id);

        let user_id_random = UserId::new_random();
        assert_ne!(user_id_random, user_id);
    }
}
