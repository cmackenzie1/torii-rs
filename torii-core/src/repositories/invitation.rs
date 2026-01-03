//! Repository trait for invitation data access.

use async_trait::async_trait;

use crate::{Error, Invitation, InvitationId, InvitationStatus, UserId};

/// Repository for invitation data access.
///
/// This trait defines the operations for managing invitations in storage.
/// Implementations should handle the underlying database operations.
#[async_trait]
pub trait InvitationRepository: Send + Sync + 'static {
    /// Create a new invitation.
    ///
    /// The invitation should include the token hash, not the plaintext token.
    async fn create(&self, invitation: &Invitation) -> Result<Invitation, Error>;

    /// Find an invitation by its ID.
    async fn find_by_id(&self, id: &InvitationId) -> Result<Option<Invitation>, Error>;

    /// Find an invitation by its token hash.
    ///
    /// This is used during token verification to look up the invitation.
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>, Error>;

    /// Find all invitations for an email address.
    ///
    /// Returns all invitations (regardless of status) for the given email,
    /// ordered by creation date descending (newest first).
    async fn find_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error>;

    /// Find all pending invitations for an email address.
    ///
    /// Returns only pending (not accepted, revoked, or expired) invitations.
    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error>;

    /// Find all invitations sent by a specific user.
    async fn find_by_inviter(&self, inviter_id: &UserId) -> Result<Vec<Invitation>, Error>;

    /// Update an invitation's status.
    ///
    /// This is used to mark invitations as accepted, revoked, etc.
    async fn update_status(
        &self,
        id: &InvitationId,
        status: InvitationStatus,
    ) -> Result<Invitation, Error>;

    /// Mark an invitation as accepted.
    ///
    /// This updates the status to `Accepted`, sets `accepted_at` to now,
    /// and records the user ID that accepted it.
    async fn accept(&self, id: &InvitationId, accepted_by: &UserId) -> Result<Invitation, Error>;

    /// Mark an invitation as revoked.
    ///
    /// This updates the status to `Revoked` and sets `revoked_at` to now.
    async fn revoke(&self, id: &InvitationId) -> Result<Invitation, Error>;

    /// Delete an invitation.
    async fn delete(&self, id: &InvitationId) -> Result<(), Error>;

    /// Clean up expired invitations.
    ///
    /// This marks all pending invitations past their expiration as expired,
    /// or optionally deletes them entirely.
    async fn cleanup_expired(&self) -> Result<u64, Error>;

    /// Count pending invitations for an email.
    ///
    /// Useful for implementing invitation limits per email.
    async fn count_pending_by_email(&self, email: &str) -> Result<u64, Error>;
}
