use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Session, User, UserId, error::EventError, session::SessionToken};

/// Stable identifier assigned to an emitted event.
pub type EventId = uuid::Uuid;

/// Identifier for the process or replica that published an event.
pub type ReplicaId = uuid::Uuid;

/// Reason why an account was unlocked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnlockReason {
    /// Account was unlocked via password reset
    PasswordReset,
    /// Lockout period expired naturally
    LockoutExpired,
    /// Administrator manually unlocked the account
    AdminAction,
}

/// Represents events that can be emitted by the event bus
///
/// Events are used to notify interested parties about changes in the system state.
/// This includes user-related events (creation, updates, deletion),
/// session-related events (creation, deletion), and security-related events
/// (login failures, account lockouts).
///
/// All events contain the relevant data needed to handle the event, such as
/// the affected User or Session objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    // User events
    UserCreated(User),
    UserUpdated(User),
    UserDeleted(UserId),

    // Session events
    SessionCreated(UserId, Session),
    SessionDeleted(UserId, SessionToken),
    SessionsCleared(UserId),
    SessionRefreshed(UserId, Session),

    // Password authentication events
    PasswordRegistered(UserId),
    PasswordAuthenticated(UserId),
    PasswordChanged(UserId),
    PasswordRemoved(UserId),
    PasswordResetRequested(UserId),
    PasswordResetCompleted(UserId),

    // OAuth events
    OAuthAuthenticated {
        user_id: UserId,
        provider: String,
    },
    OAuthAccountLinked {
        user_id: UserId,
        provider: String,
    },
    OAuthAccountUnlinked {
        user_id: UserId,
        provider: String,
    },

    // Passkey events
    PasskeyRegistered(UserId),
    PasskeyAuthenticated(UserId),
    PasskeyRemoved(UserId),

    // Magic-link and email-verification events
    MagicLinkRequested(UserId),
    MagicLinkAuthenticated(UserId),
    EmailVerificationRequested(UserId),
    EmailVerified(UserId),

    // Security events for brute force protection
    /// Emitted when a login attempt fails.
    ///
    /// This event is useful for security monitoring and audit logging.
    LoginFailed {
        /// The email address that was attempted
        email: String,
        /// Number of failed attempts in the current lockout window
        failed_attempts: u32,
        /// IP address of the client (if available)
        ip_address: Option<String>,
        /// When the attempt occurred
        timestamp: DateTime<Utc>,
    },

    /// Emitted when an account becomes locked due to too many failed attempts.
    ///
    /// This is a security-critical event that should trigger alerts.
    AccountLocked {
        /// The email address that was locked
        email: String,
        /// Number of failed attempts that triggered the lockout
        failed_attempts: u32,
        /// When the lockout will expire
        locked_until: DateTime<Utc>,
        /// IP address of the last failed attempt (if available)
        ip_address: Option<String>,
        /// When the lockout was triggered
        timestamp: DateTime<Utc>,
    },

    /// Emitted when an account is unlocked.
    ///
    /// This can occur via password reset, lockout expiry, or admin action.
    AccountUnlocked {
        /// The email address that was unlocked
        email: String,
        /// Why the account was unlocked
        reason: UnlockReason,
        /// When the unlock occurred
        timestamp: DateTime<Utc>,
    },
}

/// Event data sent between local and distributed event transports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Unique identifier for this event publication.
    pub id: EventId,
    /// Replica that originated the event.
    pub origin: ReplicaId,
    /// Time at which the event was created.
    pub occurred_at: DateTime<Utc>,
    /// Domain event payload.
    pub event: Event,
}

impl EventEnvelope {
    /// Create an envelope for a newly published event.
    pub fn new(event: Event, origin: ReplicaId) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            origin,
            occurred_at: Utc::now(),
            event,
        }
    }
}

/// A trait for handling events emitted by the event bus
///
/// Implementors of this trait can be registered with the [`torii_services::EventBus`] to receive and process events.
/// The handler is called asynchronously for each event emitted.
///
/// # Errors
///
/// Returns an [`Error`] if event handling fails. The error will be propagated back through the event bus.
///
/// # Examples
///
/// ```
/// # use torii_core::events::{Event, EventHandler};
/// # use async_trait::async_trait;
/// struct MyHandler;
///
/// #[async_trait]
/// impl EventHandler for MyHandler {
///     async fn handle(&self, event: &Event) -> Result<(), Error> {
///         // Handle the event...
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait EventHandler: Send + Sync + 'static {
    async fn handle_event(&self, event: &Event) -> Result<(), EventError>;
}
