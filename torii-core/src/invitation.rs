//! Invitation management for user onboarding
//!
//! This module provides types and functionality for inviting users to the system.
//! Invitations allow existing users to invite new users by email, creating a provisional
//! user record that can be referenced (e.g., for sharing resources) before the invitee
//! has completed signup.
//!
//! # Workflow
//!
//! 1. An inviter creates an invitation for an email address
//! 2. A provisional user is created (status = `Provisional`)
//! 3. An invitation token is generated and sent to the invitee
//! 4. The invitee clicks the link and completes signup with any auth method
//! 5. The invitation is marked as accepted and the user becomes active

use std::str::FromStr;

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    Error, UserId,
    error::ValidationError,
    id::{generate_prefixed_id, validate_prefixed_id},
};

/// A unique identifier for an invitation.
///
/// Invitation IDs are prefixed with `inv_` followed by a base58-encoded random string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct InvitationId(String);

impl InvitationId {
    /// Create a new InvitationId from an existing string.
    pub fn new(id: &str) -> Self {
        InvitationId(id.to_string())
    }

    /// Generate a new random invitation ID.
    pub fn new_random() -> Self {
        InvitationId(generate_prefixed_id("inv"))
    }

    /// Convert to the inner string, consuming self.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Get the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Validate that this ID has the correct format for an invitation ID.
    pub fn is_valid(&self) -> bool {
        validate_prefixed_id(&self.0, "inv")
    }
}

impl Default for InvitationId {
    fn default() -> Self {
        Self::new_random()
    }
}

impl From<String> for InvitationId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for InvitationId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Display for InvitationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for InvitationId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id = InvitationId(s.to_string());
        if id.is_valid() {
            Ok(id)
        } else {
            Err(ValidationError::InvalidField(format!(
                "Invalid invitation ID format: expected 'inv_' prefix with valid base58 data, got '{}'",
                s
            ))
            .into())
        }
    }
}

/// The status of an invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvitationStatus {
    /// Invitation has been sent but not yet accepted
    Pending,
    /// Invitation has been accepted by the invitee
    Accepted,
    /// Invitation has expired (past expiration date)
    Expired,
    /// Invitation was revoked by the inviter or admin
    Revoked,
}

impl InvitationStatus {
    /// Get the string representation for storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            InvitationStatus::Pending => "pending",
            InvitationStatus::Accepted => "accepted",
            InvitationStatus::Expired => "expired",
            InvitationStatus::Revoked => "revoked",
        }
    }
}

impl FromStr for InvitationStatus {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(InvitationStatus::Pending),
            "accepted" => Ok(InvitationStatus::Accepted),
            "expired" => Ok(InvitationStatus::Expired),
            "revoked" => Ok(InvitationStatus::Revoked),
            _ => {
                Err(ValidationError::InvalidField(format!("Invalid invitation status: {s}")).into())
            }
        }
    }
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// An invitation to join the system.
///
/// Invitations are created when an existing user invites a new user by email.
/// The invitation contains a secure token that the invitee uses to complete signup.
///
/// # Security
///
/// The token is stored as a SHA256 hash in the database. The plaintext token
/// is only available when the invitation is first created and should be sent
/// to the invitee (typically via email).
#[derive(Clone)]
pub struct Invitation {
    /// Unique identifier for this invitation
    pub id: InvitationId,

    /// Email address the invitation was sent to
    pub email: String,

    /// The plaintext token (only available when created, not when loaded from storage)
    token: Option<SecretString>,

    /// SHA256 hash of the token (stored in database)
    pub token_hash: String,

    /// User ID of the person who sent the invitation (if known)
    pub inviter_id: Option<UserId>,

    /// Current status of the invitation
    pub status: InvitationStatus,

    /// Application-specific metadata (roles, permissions, team assignments, etc.)
    pub metadata: Option<serde_json::Value>,

    /// When the invitation expires
    pub expires_at: DateTime<Utc>,

    /// When the invitation was accepted (if accepted)
    pub accepted_at: Option<DateTime<Utc>>,

    /// The user ID of the account that accepted the invitation
    pub accepted_by: Option<UserId>,

    /// When the invitation was revoked (if revoked)
    pub revoked_at: Option<DateTime<Utc>>,

    /// When the invitation was created
    pub created_at: DateTime<Utc>,

    /// When the invitation was last updated
    pub updated_at: DateTime<Utc>,
}

impl Invitation {
    /// Create a new Invitation with both plaintext token and hash.
    ///
    /// This constructor is used when creating a new invitation where both
    /// the plaintext (to send to invitee) and hash (to store) are available.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: InvitationId,
        email: String,
        token: String,
        token_hash: String,
        inviter_id: Option<UserId>,
        metadata: Option<serde_json::Value>,
        expires_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            email,
            token: Some(SecretString::from(token)),
            token_hash,
            inviter_id,
            status: InvitationStatus::Pending,
            metadata,
            expires_at,
            accepted_at: None,
            accepted_by: None,
            revoked_at: None,
            created_at,
            updated_at,
        }
    }

    /// Create an Invitation from stored data (hash only, no plaintext).
    ///
    /// This constructor is used when loading an invitation from storage where
    /// only the hash is available (plaintext is never stored).
    #[allow(clippy::too_many_arguments)]
    pub fn from_storage(
        id: InvitationId,
        email: String,
        token_hash: String,
        inviter_id: Option<UserId>,
        status: InvitationStatus,
        metadata: Option<serde_json::Value>,
        expires_at: DateTime<Utc>,
        accepted_at: Option<DateTime<Utc>>,
        accepted_by: Option<UserId>,
        revoked_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            email,
            token: None,
            token_hash,
            inviter_id,
            status,
            metadata,
            expires_at,
            accepted_at,
            accepted_by,
            revoked_at,
            created_at,
            updated_at,
        }
    }

    /// Get the plaintext token value.
    ///
    /// This is only available when the invitation was just created.
    /// Returns `None` when loaded from storage.
    pub fn token(&self) -> Option<&str> {
        self.token.as_ref().map(|s| s.expose_secret())
    }

    /// Verify a plaintext token against this invitation's hash.
    pub fn verify(&self, token: &str) -> bool {
        crate::crypto::verify_token_hash(token, &self.token_hash)
    }

    /// Check if the invitation has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the invitation is still pending and not expired.
    pub fn is_valid(&self) -> bool {
        self.status == InvitationStatus::Pending && !self.is_expired()
    }

    /// Check if the invitation can be accepted.
    pub fn can_accept(&self) -> bool {
        self.is_valid()
    }
}

impl std::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invitation")
            .field("id", &self.id)
            .field("email", &self.email)
            .field("token", &"[REDACTED]")
            .field("token_hash", &self.token_hash)
            .field("inviter_id", &self.inviter_id)
            .field("status", &self.status)
            .field("metadata", &self.metadata)
            .field("expires_at", &self.expires_at)
            .field("accepted_at", &self.accepted_at)
            .field("accepted_by", &self.accepted_by)
            .field("revoked_at", &self.revoked_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Data required to create a new invitation.
#[derive(Debug, Clone)]
pub struct NewInvitation {
    /// Email address to invite
    pub email: String,

    /// User ID of the inviter (optional)
    pub inviter_id: Option<UserId>,

    /// Application-specific metadata
    pub metadata: Option<serde_json::Value>,

    /// When the invitation expires
    pub expires_at: DateTime<Utc>,
}

impl NewInvitation {
    /// Create a new invitation builder.
    pub fn builder() -> NewInvitationBuilder {
        NewInvitationBuilder::default()
    }
}

/// Builder for creating new invitations.
#[derive(Default)]
pub struct NewInvitationBuilder {
    email: Option<String>,
    inviter_id: Option<UserId>,
    metadata: Option<serde_json::Value>,
    expires_at: Option<DateTime<Utc>>,
}

impl NewInvitationBuilder {
    /// Set the email address to invite.
    pub fn email(mut self, email: String) -> Self {
        self.email = Some(email);
        self
    }

    /// Set the inviter's user ID.
    pub fn inviter_id(mut self, inviter_id: UserId) -> Self {
        self.inviter_id = Some(inviter_id);
        self
    }

    /// Set application-specific metadata.
    pub fn metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set when the invitation expires.
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Build the new invitation.
    pub fn build(self) -> Result<NewInvitation, Error> {
        use crate::error::utilities::RequiredFieldExt;

        Ok(NewInvitation {
            email: self.email.require_field("email")?,
            inviter_id: self.inviter_id,
            metadata: self.metadata,
            expires_at: self.expires_at.require_field("expires_at")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_id_generation() {
        let id = InvitationId::new_random();
        assert!(id.as_str().starts_with("inv_"));
        assert!(id.is_valid());
    }

    #[test]
    fn test_invitation_id_uniqueness() {
        let id1 = InvitationId::new_random();
        let id2 = InvitationId::new_random();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_invitation_id_from_str() {
        let id = InvitationId::new_random();
        let parsed: InvitationId = id.as_str().parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_invitation_id_invalid() {
        let result: Result<InvitationId, _> = "invalid".parse();
        assert!(result.is_err());

        let result: Result<InvitationId, _> = "usr_abc".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_invitation_status_roundtrip() {
        for status in [
            InvitationStatus::Pending,
            InvitationStatus::Accepted,
            InvitationStatus::Expired,
            InvitationStatus::Revoked,
        ] {
            let s = status.as_str();
            let parsed: InvitationStatus = s.parse().unwrap();
            assert_eq!(status, parsed);
        }
    }

    #[test]
    fn test_invitation_is_expired() {
        use chrono::Duration;

        let now = Utc::now();

        // Not expired
        let invitation = Invitation::new(
            InvitationId::new_random(),
            "test@example.com".to_string(),
            "token".to_string(),
            "hash".to_string(),
            None,
            None,
            now + Duration::hours(24),
            now,
            now,
        );
        assert!(!invitation.is_expired());
        assert!(invitation.is_valid());

        // Expired
        let expired_invitation = Invitation::new(
            InvitationId::new_random(),
            "test@example.com".to_string(),
            "token".to_string(),
            "hash".to_string(),
            None,
            None,
            now - Duration::hours(1),
            now - Duration::hours(25),
            now - Duration::hours(25),
        );
        assert!(expired_invitation.is_expired());
        assert!(!expired_invitation.is_valid());
    }

    #[test]
    fn test_new_invitation_builder() {
        use chrono::Duration;

        let expires_at = Utc::now() + Duration::days(7);
        let invitation = NewInvitation::builder()
            .email("test@example.com".to_string())
            .inviter_id(UserId::new_random())
            .expires_at(expires_at)
            .build()
            .unwrap();

        assert_eq!(invitation.email, "test@example.com");
        assert!(invitation.inviter_id.is_some());
        assert_eq!(invitation.expires_at, expires_at);
    }

    #[test]
    fn test_new_invitation_builder_missing_fields() {
        let result = NewInvitation::builder().build();
        assert!(result.is_err());

        let result = NewInvitation::builder()
            .email("test@example.com".to_string())
            .build();
        assert!(result.is_err()); // Missing expires_at
    }
}
