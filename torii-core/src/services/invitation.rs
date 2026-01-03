//! Invitation service for user onboarding
//!
//! This service handles the creation and management of user invitations,
//! including creating provisional users and managing invitation tokens.

use std::sync::Arc;

use chrono::{Duration, Utc};

use crate::{
    Error, Invitation, InvitationId, User, UserId,
    crypto::{generate_secure_token, hash_token},
    error::AuthError,
    repositories::{InvitationRepository, UserRepository},
    storage::NewUser,
    user::UserStatus,
    validation::validate_email,
};

/// Configuration for the invitation service.
#[derive(Debug, Clone)]
pub struct InvitationConfig {
    /// How long invitations are valid before expiring.
    /// Default: 7 days
    pub expires_in: Duration,

    /// Whether to create a provisional user when an invitation is created.
    /// If true, a user record with `status = Provisional` is created immediately.
    /// If false, no user is created until the invitation is accepted.
    /// Default: true
    pub create_provisional_user: bool,

    /// Maximum number of pending invitations per email address.
    /// If exceeded, new invitations will fail.
    /// Default: 5
    pub max_pending_per_email: u64,
}

impl Default for InvitationConfig {
    fn default() -> Self {
        Self {
            expires_in: Duration::days(7),
            create_provisional_user: true,
            max_pending_per_email: 5,
        }
    }
}

/// Service for managing user invitations.
///
/// This service handles:
/// - Creating invitations and optional provisional users
/// - Validating and accepting invitation tokens
/// - Revoking invitations
/// - Listing pending invitations
pub struct InvitationService<I: InvitationRepository, U: UserRepository> {
    invitation_repository: Arc<I>,
    user_repository: Arc<U>,
    config: InvitationConfig,
}

impl<I: InvitationRepository, U: UserRepository> InvitationService<I, U> {
    /// Create a new InvitationService with the given repositories and default config.
    pub fn new(invitation_repository: Arc<I>, user_repository: Arc<U>) -> Self {
        Self {
            invitation_repository,
            user_repository,
            config: InvitationConfig::default(),
        }
    }

    /// Create a new InvitationService with custom configuration.
    pub fn with_config(
        invitation_repository: Arc<I>,
        user_repository: Arc<U>,
        config: InvitationConfig,
    ) -> Self {
        Self {
            invitation_repository,
            user_repository,
            config,
        }
    }

    /// Create a new invitation.
    ///
    /// This will:
    /// 1. Check if the email already has too many pending invitations
    /// 2. Optionally create a provisional user (if configured and user doesn't exist)
    /// 3. Generate a secure invitation token
    /// 4. Store the invitation
    ///
    /// Returns the invitation with the plaintext token (for sending to the invitee).
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to invite
    /// * `inviter_id` - Optional user ID of the person creating the invitation
    /// * `metadata` - Optional application-specific data (roles, permissions, etc.)
    pub async fn create_invitation(
        &self,
        email: &str,
        inviter_id: Option<UserId>,
        metadata: Option<serde_json::Value>,
    ) -> Result<(Invitation, Option<User>), Error> {
        self.create_invitation_with_expiration(email, inviter_id, metadata, self.config.expires_in)
            .await
    }

    /// Create a new invitation with custom expiration.
    pub async fn create_invitation_with_expiration(
        &self,
        email: &str,
        inviter_id: Option<UserId>,
        metadata: Option<serde_json::Value>,
        expires_in: Duration,
    ) -> Result<(Invitation, Option<User>), Error> {
        // Validate email format
        validate_email(email)?;

        // Check for existing pending invitations
        let pending_count = self
            .invitation_repository
            .count_pending_by_email(email)
            .await?;

        if pending_count >= self.config.max_pending_per_email {
            return Err(Error::Validation(
                crate::error::ValidationError::InvalidField(format!(
                    "Too many pending invitations for email: {email}"
                )),
            ));
        }

        // Check if user already exists
        let existing_user = self.user_repository.find_by_email(email).await?;

        // Create provisional user if configured and user doesn't exist
        let provisional_user = if self.config.create_provisional_user && existing_user.is_none() {
            let mut builder = NewUser::builder()
                .email(email.to_string())
                .status(UserStatus::Provisional);

            // Only set invited_by if we have an actual inviter
            if let Some(ref inviter) = inviter_id {
                builder = builder.invited_by(inviter.clone());
            }

            Some(self.user_repository.create(builder.build()?).await?)
        } else {
            None
        };

        // Generate secure token
        let token = generate_secure_token();
        let token_hash = hash_token(&token);
        let now = Utc::now();
        let expires_at = now + expires_in;

        // Create invitation
        let invitation = Invitation::new(
            InvitationId::new_random(),
            email.to_string(),
            token,
            token_hash,
            inviter_id,
            metadata,
            expires_at,
            now,
            now,
        );

        let stored_invitation = self.invitation_repository.create(&invitation).await?;

        // Return invitation with plaintext token
        Ok((
            Invitation::new(
                stored_invitation.id,
                stored_invitation.email,
                invitation.token().unwrap().to_string(),
                stored_invitation.token_hash,
                stored_invitation.inviter_id,
                stored_invitation.metadata,
                stored_invitation.expires_at,
                stored_invitation.created_at,
                stored_invitation.updated_at,
            ),
            provisional_user,
        ))
    }

    /// Get an invitation by its token.
    ///
    /// This validates the token and returns the invitation if found and valid.
    /// Does not consume the token.
    pub async fn get_invitation_by_token(&self, token: &str) -> Result<Option<Invitation>, Error> {
        let token_hash = hash_token(token);
        let invitation = self
            .invitation_repository
            .find_by_token_hash(&token_hash)
            .await?;

        // Token hash lookup is deterministic (SHA256), so if we found a match
        // we just need to check validity (not expired, still pending)
        match invitation {
            Some(inv) if inv.is_valid() => Ok(Some(inv)),
            _ => Ok(None),
        }
    }

    /// Verify an invitation token without consuming it.
    ///
    /// Returns true if the token is valid and the invitation can be accepted.
    pub async fn verify_token(&self, token: &str) -> Result<bool, Error> {
        let invitation = self.get_invitation_by_token(token).await?;
        Ok(invitation.map(|inv| inv.can_accept()).unwrap_or(false))
    }

    /// Accept an invitation.
    ///
    /// This will:
    /// 1. Verify the token is valid
    /// 2. Mark the invitation as accepted
    /// 3. If a provisional user exists, activate them
    /// 4. Return the user associated with this invitation
    ///
    /// # Arguments
    ///
    /// * `token` - The invitation token
    /// * `user_id` - The user ID accepting the invitation (may be a new user or existing)
    pub async fn accept_invitation(
        &self,
        token: &str,
        user_id: &UserId,
    ) -> Result<(Invitation, User), Error> {
        let token_hash = hash_token(token);
        let invitation = self
            .invitation_repository
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(Error::Auth(AuthError::InvalidCredentials))?;

        // Verify token and check if invitation can be accepted
        if !invitation.verify(token) {
            return Err(Error::Auth(AuthError::InvalidCredentials));
        }

        if !invitation.can_accept() {
            if invitation.is_expired() {
                return Err(Error::Validation(
                    crate::error::ValidationError::InvalidField(
                        "Invitation has expired".to_string(),
                    ),
                ));
            }
            return Err(Error::Validation(
                crate::error::ValidationError::InvalidField(format!(
                    "Invitation cannot be accepted (status: {})",
                    invitation.status
                )),
            ));
        }

        // Mark invitation as accepted
        let accepted_invitation = self
            .invitation_repository
            .accept(&invitation.id, user_id)
            .await?;

        // Get or activate the user
        let user = self
            .user_repository
            .find_by_id(user_id)
            .await?
            .ok_or(Error::Auth(AuthError::UserNotFound))?;

        // If user is provisional, activate them
        let user = if user.is_provisional() {
            let mut activated_user = user;
            activated_user.status = UserStatus::Active;
            self.user_repository.update(&activated_user).await?
        } else {
            user
        };

        Ok((accepted_invitation, user))
    }

    /// Revoke an invitation.
    ///
    /// This marks the invitation as revoked, preventing it from being accepted.
    pub async fn revoke_invitation(&self, id: &InvitationId) -> Result<Invitation, Error> {
        self.invitation_repository.revoke(id).await
    }

    /// Get an invitation by its ID.
    pub async fn get_invitation(&self, id: &InvitationId) -> Result<Option<Invitation>, Error> {
        self.invitation_repository.find_by_id(id).await
    }

    /// List all pending invitations for an email address.
    pub async fn list_pending_invitations(&self, email: &str) -> Result<Vec<Invitation>, Error> {
        self.invitation_repository
            .find_pending_by_email(email)
            .await
    }

    /// List all invitations sent by a user.
    pub async fn list_invitations_by_inviter(
        &self,
        inviter_id: &UserId,
    ) -> Result<Vec<Invitation>, Error> {
        self.invitation_repository.find_by_inviter(inviter_id).await
    }

    /// Clean up expired invitations.
    ///
    /// Returns the number of invitations that were expired.
    pub async fn cleanup_expired(&self) -> Result<u64, Error> {
        self.invitation_repository.cleanup_expired().await
    }

    /// Accept pending invitations for a user after signup.
    ///
    /// This is called after a user completes signup to automatically accept
    /// any pending invitations for their email address. This enables the
    /// flow where a user can be invited and then sign up with any auth method.
    ///
    /// Returns the list of accepted invitations.
    pub async fn accept_pending_invitations_for_user(
        &self,
        user: &User,
    ) -> Result<Vec<Invitation>, Error> {
        let pending = self
            .invitation_repository
            .find_pending_by_email(&user.email)
            .await?;

        let mut accepted = Vec::new();

        for invitation in pending {
            if invitation.can_accept() {
                let accepted_inv = self
                    .invitation_repository
                    .accept(&invitation.id, &user.id)
                    .await?;
                accepted.push(accepted_inv);
            }
        }

        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InvitationStatus;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Mock InvitationRepository
    struct MockInvitationRepository {
        invitations: Mutex<HashMap<String, Invitation>>,
    }

    impl MockInvitationRepository {
        fn new() -> Self {
            Self {
                invitations: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl InvitationRepository for MockInvitationRepository {
        async fn create(&self, invitation: &Invitation) -> Result<Invitation, Error> {
            let mut invitations = self.invitations.lock().unwrap();
            invitations.insert(invitation.id.as_str().to_string(), invitation.clone());
            Ok(invitation.clone())
        }

        async fn find_by_id(&self, id: &InvitationId) -> Result<Option<Invitation>, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations.get(id.as_str()).cloned())
        }

        async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations
                .values()
                .find(|inv| inv.token_hash == token_hash)
                .cloned())
        }

        async fn find_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations
                .values()
                .filter(|inv| inv.email == email)
                .cloned()
                .collect())
        }

        async fn find_pending_by_email(&self, email: &str) -> Result<Vec<Invitation>, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations
                .values()
                .filter(|inv| inv.email == email && inv.status == InvitationStatus::Pending)
                .cloned()
                .collect())
        }

        async fn find_by_inviter(&self, inviter_id: &UserId) -> Result<Vec<Invitation>, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations
                .values()
                .filter(|inv| inv.inviter_id.as_ref() == Some(inviter_id))
                .cloned()
                .collect())
        }

        async fn update_status(
            &self,
            id: &InvitationId,
            status: InvitationStatus,
        ) -> Result<Invitation, Error> {
            let mut invitations = self.invitations.lock().unwrap();
            if let Some(inv) = invitations.get_mut(id.as_str()) {
                let updated = Invitation::from_storage(
                    inv.id.clone(),
                    inv.email.clone(),
                    inv.token_hash.clone(),
                    inv.inviter_id.clone(),
                    status,
                    inv.metadata.clone(),
                    inv.expires_at,
                    inv.accepted_at,
                    inv.accepted_by.clone(),
                    inv.revoked_at,
                    inv.created_at,
                    Utc::now(),
                );
                *inv = updated.clone();
                Ok(updated)
            } else {
                Err(Error::Storage(crate::error::StorageError::NotFound))
            }
        }

        async fn accept(
            &self,
            id: &InvitationId,
            accepted_by: &UserId,
        ) -> Result<Invitation, Error> {
            let mut invitations = self.invitations.lock().unwrap();
            if let Some(inv) = invitations.get_mut(id.as_str()) {
                let now = Utc::now();
                let updated = Invitation::from_storage(
                    inv.id.clone(),
                    inv.email.clone(),
                    inv.token_hash.clone(),
                    inv.inviter_id.clone(),
                    InvitationStatus::Accepted,
                    inv.metadata.clone(),
                    inv.expires_at,
                    Some(now),
                    Some(accepted_by.clone()),
                    None,
                    inv.created_at,
                    now,
                );
                *inv = updated.clone();
                Ok(updated)
            } else {
                Err(Error::Storage(crate::error::StorageError::NotFound))
            }
        }

        async fn revoke(&self, id: &InvitationId) -> Result<Invitation, Error> {
            let mut invitations = self.invitations.lock().unwrap();
            if let Some(inv) = invitations.get_mut(id.as_str()) {
                let now = Utc::now();
                let updated = Invitation::from_storage(
                    inv.id.clone(),
                    inv.email.clone(),
                    inv.token_hash.clone(),
                    inv.inviter_id.clone(),
                    InvitationStatus::Revoked,
                    inv.metadata.clone(),
                    inv.expires_at,
                    None,
                    None,
                    Some(now),
                    inv.created_at,
                    now,
                );
                *inv = updated.clone();
                Ok(updated)
            } else {
                Err(Error::Storage(crate::error::StorageError::NotFound))
            }
        }

        async fn delete(&self, id: &InvitationId) -> Result<(), Error> {
            let mut invitations = self.invitations.lock().unwrap();
            invitations.remove(id.as_str());
            Ok(())
        }

        async fn cleanup_expired(&self) -> Result<u64, Error> {
            let mut invitations = self.invitations.lock().unwrap();
            let now = Utc::now();
            let expired_ids: Vec<_> = invitations
                .iter()
                .filter(|(_, inv)| inv.status == InvitationStatus::Pending && inv.expires_at < now)
                .map(|(id, _)| id.clone())
                .collect();

            let count = expired_ids.len() as u64;
            for id in expired_ids {
                if let Some(inv) = invitations.get_mut(&id) {
                    let updated = Invitation::from_storage(
                        inv.id.clone(),
                        inv.email.clone(),
                        inv.token_hash.clone(),
                        inv.inviter_id.clone(),
                        InvitationStatus::Expired,
                        inv.metadata.clone(),
                        inv.expires_at,
                        None,
                        None,
                        None,
                        inv.created_at,
                        now,
                    );
                    *inv = updated;
                }
            }
            Ok(count)
        }

        async fn count_pending_by_email(&self, email: &str) -> Result<u64, Error> {
            let invitations = self.invitations.lock().unwrap();
            Ok(invitations
                .values()
                .filter(|inv| inv.email == email && inv.status == InvitationStatus::Pending)
                .count() as u64)
        }
    }

    // Mock UserRepository
    struct MockUserRepository {
        users: Mutex<HashMap<String, User>>,
    }

    impl MockUserRepository {
        fn new() -> Self {
            Self {
                users: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn create(&self, user: NewUser) -> Result<User, Error> {
            let now = Utc::now();
            let created = User::builder()
                .id(user.id.clone())
                .email(user.email.clone())
                .name(user.name)
                .email_verified_at(user.email_verified_at)
                .status(user.status)
                .invited_by(user.invited_by)
                .created_at(now)
                .updated_at(now)
                .build()?;

            let mut users = self.users.lock().unwrap();
            users.insert(user.id.as_str().to_string(), created.clone());
            Ok(created)
        }

        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, Error> {
            let users = self.users.lock().unwrap();
            Ok(users.get(id.as_str()).cloned())
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, Error> {
            let users = self.users.lock().unwrap();
            Ok(users.values().find(|u| u.email == email).cloned())
        }

        async fn find_or_create_by_email(&self, email: &str) -> Result<User, Error> {
            if let Some(user) = self.find_by_email(email).await? {
                Ok(user)
            } else {
                self.create(NewUser::new(email.to_string())).await
            }
        }

        async fn update(&self, user: &User) -> Result<User, Error> {
            let mut users = self.users.lock().unwrap();
            users.insert(user.id.as_str().to_string(), user.clone());
            Ok(user.clone())
        }

        async fn delete(&self, id: &UserId) -> Result<(), Error> {
            let mut users = self.users.lock().unwrap();
            users.remove(id.as_str());
            Ok(())
        }

        async fn mark_email_verified(&self, user_id: &UserId) -> Result<(), Error> {
            let mut users = self.users.lock().unwrap();
            if let Some(user) = users.get_mut(user_id.as_str()) {
                user.email_verified_at = Some(Utc::now());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_invitation() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo.clone(), user_repo.clone());

        let (invitation, user) = service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        assert_eq!(invitation.email, "test@example.com");
        assert!(invitation.token().is_some());
        assert_eq!(invitation.status, InvitationStatus::Pending);
        assert!(user.is_some()); // Provisional user created

        let user = user.unwrap();
        assert_eq!(user.status, UserStatus::Provisional);
    }

    #[tokio::test]
    async fn test_verify_token() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo, user_repo);

        let (invitation, _) = service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        let token = invitation.token().unwrap().to_string();

        // Valid token
        assert!(service.verify_token(&token).await.unwrap());

        // Invalid token
        assert!(!service.verify_token("invalid").await.unwrap());
    }

    #[tokio::test]
    async fn test_accept_invitation() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo, user_repo);

        let (invitation, user) = service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        let token = invitation.token().unwrap().to_string();
        let provisional_user = user.unwrap();

        let (accepted_inv, activated_user) = service
            .accept_invitation(&token, &provisional_user.id)
            .await
            .unwrap();

        assert_eq!(accepted_inv.status, InvitationStatus::Accepted);
        assert!(accepted_inv.accepted_at.is_some());
        assert_eq!(activated_user.status, UserStatus::Active);
    }

    #[tokio::test]
    async fn test_revoke_invitation() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo, user_repo);

        let (invitation, _) = service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        let revoked = service.revoke_invitation(&invitation.id).await.unwrap();

        assert_eq!(revoked.status, InvitationStatus::Revoked);
        assert!(revoked.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_max_pending_invitations() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let config = InvitationConfig {
            max_pending_per_email: 2,
            create_provisional_user: false, // Disable to avoid unique constraint on email
            ..Default::default()
        };
        let service = InvitationService::with_config(invitation_repo, user_repo, config);

        // First two should succeed
        service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();
        service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        // Third should fail
        let result = service
            .create_invitation("test@example.com", None, None)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_create_invitation_validates_email() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo, user_repo);

        // Invalid email should fail
        let result = service.create_invitation("invalid-email", None, None).await;
        assert!(result.is_err());

        // Empty email should fail
        let result = service.create_invitation("", None, None).await;
        assert!(result.is_err());

        // Valid email should succeed
        let result = service
            .create_invitation("valid@example.com", None, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_create_invitation_without_inviter_has_no_invited_by() {
        let invitation_repo = Arc::new(MockInvitationRepository::new());
        let user_repo = Arc::new(MockUserRepository::new());
        let service = InvitationService::new(invitation_repo, user_repo);

        // Create invitation without inviter
        let (_, provisional_user) = service
            .create_invitation("test@example.com", None, None)
            .await
            .unwrap();

        // Provisional user should have no invited_by
        let user = provisional_user.unwrap();
        assert!(user.invited_by.is_none());
    }
}
