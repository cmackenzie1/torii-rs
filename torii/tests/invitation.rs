use std::sync::Arc;

use torii::{InvitationStatus, Torii, UserStatus};
use torii_core::repositories::RepositoryProvider;

// Invitation functionality is only implemented for PostgreSQL currently
// SQLite and SeaORM have stub implementations that return errors

#[cfg(feature = "postgres")]
use torii::postgres::PostgresRepositoryProvider;

/// Helper to set up a PostgreSQL test database
#[cfg(feature = "postgres")]
async fn setup_postgres() -> PostgresRepositoryProvider {
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/torii_test".into());
    let pool = sqlx::PgPool::connect(&database_url).await.unwrap();
    let provider = PostgresRepositoryProvider::new(pool);
    provider.migrate().await.unwrap();
    provider
}

/// Test creating an invitation and verifying its properties
#[cfg(all(feature = "password", feature = "postgres"))]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_create_invitation() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an inviter user first
    let inviter_email = "inviter@example.com";
    let inviter_password = "password123";
    let inviter = torii
        .password()
        .register(inviter_email, inviter_password)
        .await
        .unwrap();

    // Create an invitation
    let invitee_email = "invitee@example.com";
    let (invitation, provisional_user) = torii
        .create_invitation(
            invitee_email,
            Some(&inviter.id),
            "https://example.com/invite",
            None,
        )
        .await
        .unwrap();

    // Verify invitation properties
    assert_eq!(invitation.email, invitee_email);
    assert_eq!(invitation.inviter_id.as_ref(), Some(&inviter.id));
    assert_eq!(invitation.status, InvitationStatus::Pending);
    assert!(!invitation.is_expired());
    assert!(invitation.can_accept());

    // Verify the token is available
    assert!(invitation.token().is_some());

    // Verify a provisional user was created
    assert!(provisional_user.is_some());
    let provisional = provisional_user.unwrap();
    assert_eq!(provisional.email, invitee_email);
    assert_eq!(provisional.status, UserStatus::Provisional);
    assert!(provisional.is_provisional());
    assert!(!provisional.is_active());
}

/// Test verifying an invitation token
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_verify_invitation_token() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an invitation (without inviter for simplicity)
    let invitee_email = "verify@example.com";
    let (invitation, _) = torii
        .create_invitation(invitee_email, None, "https://example.com/invite", None)
        .await
        .unwrap();

    // Get the token
    let token = invitation.token().unwrap();

    // Verify the token
    let verified = torii.verify_invitation_token(token).await.unwrap();
    assert!(verified.is_some());
    let verified_invitation = verified.unwrap();
    assert_eq!(verified_invitation.email, invitee_email);

    // Verify with invalid token fails
    let invalid = torii
        .verify_invitation_token("invalid_token")
        .await
        .unwrap();
    assert!(invalid.is_none());
}

/// Test accepting an invitation
#[cfg(all(feature = "password", feature = "postgres"))]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_accept_invitation() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an inviter user
    let inviter_email = "inviter@example.com";
    let inviter = torii
        .password()
        .register(inviter_email, "password123")
        .await
        .unwrap();

    // Create an invitation
    let invitee_email = "newuser@example.com";
    let (invitation, provisional_user) = torii
        .create_invitation(
            invitee_email,
            Some(&inviter.id),
            "https://example.com/invite",
            None,
        )
        .await
        .unwrap();

    // Get the provisional user ID
    let provisional = provisional_user.expect("Provisional user should be created");
    let token = invitation.token().unwrap();

    // Accept the invitation
    let (accepted_invitation, activated_user) = torii
        .accept_invitation(token, &provisional.id)
        .await
        .unwrap();

    // Verify invitation is now accepted
    assert_eq!(accepted_invitation.status, InvitationStatus::Accepted);

    // Verify user is now active
    assert_eq!(activated_user.status, UserStatus::Active);
    assert!(activated_user.is_active());
    assert!(!activated_user.is_provisional());
}

/// Test revoking an invitation
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_revoke_invitation() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an invitation
    let invitee_email = "revoke@example.com";
    let (invitation, _) = torii
        .create_invitation(invitee_email, None, "https://example.com/invite", None)
        .await
        .unwrap();

    // Revoke the invitation
    let revoked = torii.revoke_invitation(&invitation.id).await.unwrap();

    // Verify invitation is revoked
    assert_eq!(revoked.status, InvitationStatus::Revoked);
    assert!(!revoked.can_accept());

    // Verify the token no longer works
    let token = invitation.token().unwrap();
    let verified = torii.verify_invitation_token(token).await.unwrap();
    assert!(verified.is_none()); // Should not return revoked invitations
}

/// Test listing pending invitations
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_list_pending_invitations() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create multiple invitations for the same email
    let email = "multi@example.com";
    let (_inv1, _) = torii
        .create_invitation(email, None, "https://example.com/invite", None)
        .await
        .unwrap();
    let (_inv2, _) = torii
        .create_invitation(email, None, "https://example.com/invite", None)
        .await
        .unwrap();

    // List pending invitations
    let pending = torii.list_pending_invitations(email).await.unwrap();
    assert_eq!(pending.len(), 2);

    // All should be pending
    for inv in &pending {
        assert_eq!(inv.status, InvitationStatus::Pending);
    }
}

/// Test that invitations by inviter are tracked
#[cfg(all(feature = "password", feature = "postgres"))]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_list_invitations_by_inviter() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an inviter
    let inviter = torii
        .password()
        .register("inviter@example.com", "password123")
        .await
        .unwrap();

    // Create invitations from this inviter
    torii
        .create_invitation(
            "user1@example.com",
            Some(&inviter.id),
            "https://example.com/invite",
            None,
        )
        .await
        .unwrap();
    torii
        .create_invitation(
            "user2@example.com",
            Some(&inviter.id),
            "https://example.com/invite",
            None,
        )
        .await
        .unwrap();

    // List invitations sent by this inviter
    let sent = torii
        .list_invitations_by_inviter(&inviter.id)
        .await
        .unwrap();
    assert_eq!(sent.len(), 2);
}

/// Test auto-accepting pending invitations after signup
#[cfg(all(feature = "password", feature = "postgres"))]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_accept_pending_invitations_after_signup() {
    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create an inviter
    let inviter = torii
        .password()
        .register("inviter@example.com", "password123")
        .await
        .unwrap();

    // Create an invitation for a user who doesn't exist yet
    let new_user_email = "newuser@example.com";
    torii
        .create_invitation(
            new_user_email,
            Some(&inviter.id),
            "https://example.com/invite",
            None,
        )
        .await
        .unwrap();

    // Verify there's a pending invitation
    let pending = torii
        .list_pending_invitations(new_user_email)
        .await
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].status, InvitationStatus::Pending);

    // User signs up (not using the invitation link directly, just registering)
    let user = torii
        .password()
        .register(new_user_email, "password123")
        .await
        .unwrap();

    // Accept pending invitations for this user
    let accepted = torii.accept_pending_invitations(&user).await.unwrap();

    // Verify invitations were accepted
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].status, InvitationStatus::Accepted);

    // Verify no more pending invitations
    let remaining = torii
        .list_pending_invitations(new_user_email)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 0);
}

/// Test invitation with metadata
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "Requires PostgreSQL database"]
async fn test_invitation_with_metadata() {
    use serde_json::json;

    // Set up PostgreSQL storage
    let repositories = setup_postgres().await;

    // Create Torii instance
    let torii = Torii::new(Arc::new(repositories));

    // Create invitation with metadata
    let metadata = json!({
        "role": "admin",
        "team": "engineering"
    });

    let (invitation, _) = torii
        .create_invitation(
            "metadata@example.com",
            None,
            "https://example.com/invite",
            Some(metadata.clone()),
        )
        .await
        .unwrap();

    // Verify metadata was stored
    assert!(invitation.metadata.is_some());
    let stored = invitation.metadata.unwrap();
    assert_eq!(stored["role"], "admin");
    assert_eq!(stored["team"], "engineering");
}
