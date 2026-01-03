//! SQLite implementation of the invitation repository.
//!
//! Note: This is a stub implementation. Full SQLite support for invitations
//! will be added in a future release.

use async_trait::async_trait;
use sqlx::SqlitePool;
use torii_core::{
    Error, Invitation, InvitationId, InvitationStatus, UserId, error::StorageError,
    repositories::InvitationRepository,
};

/// SQLite repository for invitation data.
///
/// Note: This is currently a stub implementation that returns errors
/// for all operations. Full SQLite support will be added in a future release.
pub struct SqliteInvitationRepository {
    #[allow(dead_code)]
    pool: SqlitePool,
}

impl SqliteInvitationRepository {
    /// Create a new SQLite invitation repository.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvitationRepository for SqliteInvitationRepository {
    async fn create(&self, _invitation: &Invitation) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn find_by_id(&self, _id: &InvitationId) -> Result<Option<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn find_by_token_hash(&self, _token_hash: &str) -> Result<Option<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn find_by_email(&self, _email: &str) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn find_pending_by_email(&self, _email: &str) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn find_by_inviter(&self, _inviter_id: &UserId) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn update_status(
        &self,
        _id: &InvitationId,
        _status: InvitationStatus,
    ) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn accept(&self, _id: &InvitationId, _accepted_by: &UserId) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn revoke(&self, _id: &InvitationId) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn delete(&self, _id: &InvitationId) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn cleanup_expired(&self) -> Result<u64, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }

    async fn count_pending_by_email(&self, _email: &str) -> Result<u64, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SQLite".to_string(),
        )))
    }
}
