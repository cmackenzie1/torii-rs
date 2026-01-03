//! SeaORM implementation of the invitation repository.
//!
//! Note: This is a stub implementation. Full SeaORM support for invitations
//! will be added in a future release.

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use torii_core::{
    Error, Invitation, InvitationId, InvitationStatus, UserId, error::StorageError,
    repositories::InvitationRepository,
};

/// SeaORM repository for invitation data.
///
/// Note: This is currently a stub implementation that returns errors
/// for all operations. Full SeaORM support will be added in a future release.
#[derive(Clone)]
pub struct SeaORMInvitationRepository {
    #[allow(dead_code)]
    pool: DatabaseConnection,
}

impl SeaORMInvitationRepository {
    /// Create a new SeaORM invitation repository.
    pub fn new(pool: DatabaseConnection) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvitationRepository for SeaORMInvitationRepository {
    async fn create(&self, _invitation: &Invitation) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn find_by_id(&self, _id: &InvitationId) -> Result<Option<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn find_by_token_hash(&self, _token_hash: &str) -> Result<Option<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn find_by_email(&self, _email: &str) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn find_pending_by_email(&self, _email: &str) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn find_by_inviter(&self, _inviter_id: &UserId) -> Result<Vec<Invitation>, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn update_status(
        &self,
        _id: &InvitationId,
        _status: InvitationStatus,
    ) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn accept(&self, _id: &InvitationId, _accepted_by: &UserId) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn revoke(&self, _id: &InvitationId) -> Result<Invitation, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn delete(&self, _id: &InvitationId) -> Result<(), Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn cleanup_expired(&self) -> Result<u64, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }

    async fn count_pending_by_email(&self, _email: &str) -> Result<u64, Error> {
        Err(Error::Storage(StorageError::Database(
            "Invitation repository not yet implemented for SeaORM".to_string(),
        )))
    }
}
