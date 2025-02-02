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
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A unique, stable identifier for a specific user
#[derive(Debug, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(transparent)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: &str) -> Self {
        UserId(id.to_string())
    }

    pub fn new_random() -> Self {
        UserId(Uuid::new_v4().to_string())
    }
}

impl FromStr for UserId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UserId(s.to_string()))
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    // The unique identifier for the user.
    pub id: UserId,

    // The name of the user.
    pub name: String,

    // The email of the user.
    pub email: String,

    // The email verified at timestamp. If the user has not verified their email, this will be None.
    pub email_verified_at: Option<DateTime<Utc>>,

    // The created at timestamp.
    pub created_at: DateTime<Utc>,

    // The updated at timestamp.
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        let user_id = UserId::new("test");
        assert_eq!(user_id.as_ref(), "test");

        let user_id_from_str = UserId::from_str(user_id.as_ref()).unwrap();
        assert_eq!(user_id_from_str, user_id);

        let user_id_random = UserId::new_random();
        assert_ne!(user_id_random, user_id);
    }
}
