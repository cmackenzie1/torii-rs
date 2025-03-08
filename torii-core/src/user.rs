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
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Error, error::ValidationError};

/// A unique, stable identifier for a specific user
/// This value should be treated as opaque, and should not be used as a UUID even if it may look like one
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
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

    pub fn as_str(&self) -> &str {
        &self.0
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
    pub name: Option<String>,

    // The email of the user.
    pub email: String,

    // The email verified at timestamp. If the user has not verified their email, this will be None.
    pub email_verified_at: Option<DateTime<Utc>>,

    // The created at timestamp.
    pub created_at: DateTime<Utc>,

    // The updated at timestamp.
    pub updated_at: DateTime<Utc>,
}

impl User {
    pub fn builder() -> UserBuilder {
        UserBuilder::default()
    }

    /// Check if the user's email has been verified.
    pub fn is_email_verified(&self) -> bool {
        self.email_verified_at.is_some()
    }
}

#[derive(Default)]
pub struct UserBuilder {
    id: Option<UserId>,
    name: Option<String>,
    email: Option<String>,
    email_verified_at: Option<DateTime<Utc>>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl UserBuilder {
    pub fn id(mut self, id: UserId) -> Self {
        self.id = Some(id);
        self
    }

    pub fn name(mut self, name: Option<String>) -> Self {
        self.name = name;
        self
    }

    pub fn email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    pub fn email_verified_at(mut self, email_verified_at: Option<DateTime<Utc>>) -> Self {
        self.email_verified_at = email_verified_at;
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn build(self) -> Result<User, Error> {
        let now = Utc::now();
        Ok(User {
            id: self.id.unwrap_or(UserId::new_random()),
            name: self.name,
            email: self.email.ok_or(ValidationError::InvalidField(
                "Email is required".to_string(),
            ))?,
            email_verified_at: self.email_verified_at,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthAccount {
    pub user_id: UserId,
    pub provider: String,
    pub subject: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl OAuthAccount {
    pub fn builder() -> OAuthAccountBuilder {
        OAuthAccountBuilder::default()
    }
}

#[derive(Default)]
pub struct OAuthAccountBuilder {
    user_id: Option<UserId>,
    provider: Option<String>,
    subject: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
}

impl OAuthAccountBuilder {
    pub fn user_id(mut self, user_id: UserId) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn provider(mut self, provider: String) -> Self {
        self.provider = Some(provider);
        self
    }

    pub fn subject(mut self, subject: String) -> Self {
        self.subject = Some(subject);
        self
    }

    pub fn created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }

    pub fn updated_at(mut self, updated_at: DateTime<Utc>) -> Self {
        self.updated_at = Some(updated_at);
        self
    }

    pub fn build(self) -> Result<OAuthAccount, Error> {
        let now = Utc::now();
        Ok(OAuthAccount {
            user_id: self.user_id.ok_or(ValidationError::MissingField(
                "User ID is required".to_string(),
            ))?,
            provider: self.provider.ok_or(ValidationError::MissingField(
                "Provider is required".to_string(),
            ))?,
            subject: self.subject.ok_or(ValidationError::MissingField(
                "Subject is required".to_string(),
            ))?,
            created_at: self.created_at.unwrap_or(now),
            updated_at: self.updated_at.unwrap_or(now),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id() {
        let user_id = UserId::new("test");
        assert_eq!(user_id.as_str(), "test");

        let user_id_from_str = UserId::from(user_id.as_str());
        assert_eq!(user_id_from_str, user_id);

        let user_id_random = UserId::new_random();
        assert_ne!(user_id_random, user_id);
    }
}
