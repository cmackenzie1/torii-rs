//! PostgreSQL implementation of the invitation repository.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use torii_core::{
    Error, Invitation, InvitationId, InvitationStatus, UserId, error::StorageError,
    repositories::InvitationRepository,
};

/// PostgreSQL row type for invitations.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PostgresInvitation {
    pub id: String,
    pub email: String,
    pub token_hash: String,
    pub inviter_id: Option<String>,
    pub status: String,
    pub metadata: Option<serde_json::Value>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub accepted_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<PostgresInvitation> for Invitation {
    fn from(inv: PostgresInvitation) -> Self {
        Invitation::from_storage(
            InvitationId::new(&inv.id),
            inv.email,
            inv.token_hash,
            inv.inviter_id.map(|id| UserId::new(&id)),
            inv.status.parse().unwrap_or(InvitationStatus::Pending),
            inv.metadata,
            inv.expires_at,
            inv.accepted_at,
            inv.accepted_by.map(|id| UserId::new(&id)),
            inv.revoked_at,
            inv.created_at,
            inv.updated_at,
        )
    }
}

/// PostgreSQL repository for invitation data.
pub struct PostgresInvitationRepository {
    pool: PgPool,
}

impl PostgresInvitationRepository {
    /// Create a new PostgreSQL invitation repository.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvitationRepository for PostgresInvitationRepository {
    async fn create(&self, invitation: &Invitation) -> Result<Invitation, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            INSERT INTO invitations (id, email, token_hash, inviter_id, status, metadata, expires_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            "#,
        )
        .bind(invitation.id.as_str())
        .bind(&invitation.email)
        .bind(&invitation.token_hash)
        .bind(invitation.inviter_id.as_ref().map(|id| id.as_str()))
        .bind(invitation.status.as_str())
        .bind(&invitation.metadata)
        .bind(invitation.expires_at)
        .bind(invitation.created_at)
        .bind(invitation.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create invitation");
            Error::Storage(StorageError::Database("Failed to create invitation".to_string()))
        })?;

        Ok(pg_invitation.into())
    }

    async fn find_by_id(&self, id: &InvitationId) -> Result<Option<Invitation>, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            SELECT id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            FROM invitations
            WHERE id = $1
            "#,
        )
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find invitation by ID");
            Error::Storage(StorageError::Database("Failed to find invitation by ID".to_string()))
        })?;

        Ok(pg_invitation.map(|inv| inv.into()))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            SELECT id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            FROM invitations
            WHERE token_hash = $1
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find invitation by token hash");
            Error::Storage(StorageError::Database("Failed to find invitation by token hash".to_string()))
        })?;

        Ok(pg_invitation.map(|inv| inv.into()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error> {
        let pg_invitations = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            SELECT id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            FROM invitations
            WHERE email = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find invitations by email");
            Error::Storage(StorageError::Database("Failed to find invitations by email".to_string()))
        })?;

        Ok(pg_invitations.into_iter().map(|inv| inv.into()).collect())
    }

    async fn find_pending_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error> {
        let pg_invitations = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            SELECT id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            FROM invitations
            WHERE email = $1 AND status = 'pending' AND expires_at > NOW()
            ORDER BY created_at DESC
            "#,
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find pending invitations by email");
            Error::Storage(StorageError::Database("Failed to find pending invitations by email".to_string()))
        })?;

        Ok(pg_invitations.into_iter().map(|inv| inv.into()).collect())
    }

    async fn find_by_inviter(&self, inviter_id: &UserId) -> Result<Vec<Invitation>, Error> {
        let pg_invitations = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            SELECT id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            FROM invitations
            WHERE inviter_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(inviter_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to find invitations by inviter");
            Error::Storage(StorageError::Database("Failed to find invitations by inviter".to_string()))
        })?;

        Ok(pg_invitations.into_iter().map(|inv| inv.into()).collect())
    }

    async fn update_status(
        &self,
        id: &InvitationId,
        status: InvitationStatus,
    ) -> Result<Invitation, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            UPDATE invitations
            SET status = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            "#,
        )
        .bind(status.as_str())
        .bind(id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to update invitation status");
            Error::Storage(StorageError::Database("Failed to update invitation status".to_string()))
        })?;

        Ok(pg_invitation.into())
    }

    async fn accept(&self, id: &InvitationId, accepted_by: &UserId) -> Result<Invitation, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            UPDATE invitations
            SET status = 'accepted', accepted_at = NOW(), accepted_by = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            "#,
        )
        .bind(accepted_by.as_str())
        .bind(id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to accept invitation");
            Error::Storage(StorageError::Database("Failed to accept invitation".to_string()))
        })?;

        Ok(pg_invitation.into())
    }

    async fn revoke(&self, id: &InvitationId) -> Result<Invitation, Error> {
        let pg_invitation = sqlx::query_as::<_, PostgresInvitation>(
            r#"
            UPDATE invitations
            SET status = 'revoked', revoked_at = NOW(), updated_at = NOW()
            WHERE id = $1
            RETURNING id, email, token_hash, inviter_id, status, metadata, expires_at, accepted_at, accepted_by, revoked_at, created_at, updated_at
            "#,
        )
        .bind(id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to revoke invitation");
            Error::Storage(StorageError::Database("Failed to revoke invitation".to_string()))
        })?;

        Ok(pg_invitation.into())
    }

    async fn delete(&self, id: &InvitationId) -> Result<(), Error> {
        sqlx::query("DELETE FROM invitations WHERE id = $1")
            .bind(id.as_str())
            .execute(&self.pool)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to delete invitation");
                Error::Storage(StorageError::Database(
                    "Failed to delete invitation".to_string(),
                ))
            })?;

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<u64, Error> {
        let result = sqlx::query(
            r#"
            UPDATE invitations
            SET status = 'expired', updated_at = NOW()
            WHERE status = 'pending' AND expires_at < NOW()
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to cleanup expired invitations");
            Error::Storage(StorageError::Database(
                "Failed to cleanup expired invitations".to_string(),
            ))
        })?;

        Ok(result.rows_affected())
    }

    async fn count_pending_by_email(&self, email: &str) -> Result<u64, Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM invitations
            WHERE email = $1 AND status = 'pending' AND expires_at > NOW()
            "#,
        )
        .bind(email)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to count pending invitations");
            Error::Storage(StorageError::Database(
                "Failed to count pending invitations".to_string(),
            ))
        })?;

        Ok(count as u64)
    }
}
