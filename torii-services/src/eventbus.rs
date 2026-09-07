use std::sync::Arc;

use tokio::sync::RwLock;

use async_trait::async_trait;
use torii_core::{
    error::EventError,
    events::{Event, EventEnvelope, EventHandler, ReplicaId},
};

/// A backend that publishes event envelopes to another delivery system.
#[async_trait]
pub trait EventPublisher: Send + Sync {
    /// Publish an event envelope to the backend.
    async fn publish(&self, envelope: &EventEnvelope) -> Result<(), EventError>;
}

/// Emit an event when a service has been configured with an event bus.
pub async fn emit_if_configured(
    event_bus: Option<&Arc<EventBus>>,
    event: &Event,
) -> Result<(), EventError> {
    if let Some(event_bus) = event_bus {
        event_bus.emit(event).await?;
    }

    Ok(())
}

/// Provides the shared event-emission behavior for a service.
#[async_trait]
pub trait EventEmitter {
    /// Return the event bus configured for this service, if any.
    fn event_bus(&self) -> Option<&Arc<EventBus>>;

    /// Emit an event when this service has an event bus configured.
    async fn emit_event(&self, event: Event) -> Result<(), EventError> {
        if let Some(event_bus) = self.event_bus() {
            event_bus.emit(&event).await?;
        }

        Ok(())
    }
}

/// Event bus that can emit events and register event handlers
///
/// The event bus is responsible for managing event handlers and emitting events to them.
/// It provides a simple way to register and unregister handlers, and to emit events to all registered handlers.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # use torii_core::{User, UserId, error::EventError, events::{Event, EventHandler}};
/// # use torii_services::EventBus;
/// # use async_trait::async_trait;
/// struct MyHandler;
///
/// #[async_trait]
/// impl EventHandler for MyHandler {
///     async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
///         // Handle the event...
///         Ok(())
///     }
/// }
///
/// #[tokio::main]
/// async fn main() {
///     let event_bus = EventBus::default();
///     event_bus.register(Arc::new(MyHandler)).await;
///     event_bus.emit(&Event::UserCreated(User::builder().id(UserId::new("test")).build().unwrap())).await.unwrap();
/// }
/// ```
#[derive(Clone)]
pub struct EventBus {
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
    publishers: Arc<RwLock<Vec<Arc<dyn EventPublisher>>>>,
    replica_id: ReplicaId,
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl EventBus {
    /// Create a new event bus
    ///
    /// # Examples
    ///
    /// ```
    /// # use torii_services::EventBus;
    /// let event_bus = EventBus::new();
    /// ```
    pub fn new() -> Self {
        Self {
            handlers: Arc::new(RwLock::new(Vec::new())),
            publishers: Arc::new(RwLock::new(Vec::new())),
            replica_id: ReplicaId::new_v4(),
        }
    }

    /// Register an event handler with the event bus
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use torii_core::events::{Event, EventHandler};
    /// # use torii_core::error::EventError;
    /// # use torii_services::EventBus;
    /// # use async_trait::async_trait;
    /// struct MyHandler;
    ///
    /// #[async_trait]
    /// impl EventHandler for MyHandler {
    ///     async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
    ///         // Handle the event...
    ///         Ok(())
    ///     }
    /// }
    ///
    /// # #[tokio::main]
    /// # async fn main() {
    /// let event_bus = EventBus::default();
    /// event_bus.register(Arc::new(MyHandler)).await;
    /// # }
    /// ```
    pub async fn register(&self, handler: Arc<dyn EventHandler>) {
        self.handlers.write().await.push(handler);
    }

    /// Register a publisher backend such as PostgreSQL `NOTIFY`.
    pub async fn register_publisher(&self, publisher: Arc<dyn EventPublisher>) {
        self.publishers.write().await.push(publisher);
    }

    /// Emit an event to all registered handlers
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use torii_core::{User, UserId, events::Event};
    /// # use torii_services::EventBus;
    /// # #[tokio::main]
    /// # async fn main() {
    /// let event_bus = EventBus::default();
    /// event_bus.emit(&Event::UserCreated(User::builder().id(UserId::new("test")).build().unwrap())).await.unwrap();
    /// # }
    /// ```
    pub async fn emit(&self, event: &Event) -> Result<(), EventError> {
        let envelope = EventEnvelope::new(event.clone(), self.replica_id);
        self.dispatch(&envelope).await?;

        let publishers = self.publishers.read().await.clone();
        for publisher in publishers {
            if let Err(error) = publisher.publish(&envelope).await {
                tracing::error!(event_id = %envelope.id, error = error.to_string(), "Event publisher failed");
            }
        }

        Ok(())
    }

    /// Build an envelope using this bus's replica identity.
    pub fn envelope(&self, event: Event) -> EventEnvelope {
        EventEnvelope::new(event, self.replica_id)
    }

    /// Dispatch an event received from a local or distributed transport.
    pub async fn dispatch(&self, envelope: &EventEnvelope) -> Result<(), EventError> {
        let handlers = self.handlers.read().await.clone();
        for handler in handlers {
            if let Err(error) = handler.handle_event(&envelope.event).await {
                tracing::error!(event_id = %envelope.id, error = error.to_string(), "Event handler failed");
            }
        }

        Ok(())
    }

    /// Dispatch an event envelope unless it originated from this bus.
    pub async fn dispatch_remote(&self, envelope: &EventEnvelope) -> Result<(), EventError> {
        if envelope.origin == self.replica_id {
            return Ok(());
        }

        self.dispatch(envelope).await
    }

    /// Return the identifier of this event bus's replica.
    pub fn replica_id(&self) -> ReplicaId {
        self.replica_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use torii_core::{
        User, UserId,
        session::{Session, SessionToken},
    };

    struct TestEventHandler {
        called: Arc<AtomicBool>,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl EventHandler for TestEventHandler {
        async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
            self.called.store(true, Ordering::SeqCst);
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ErroringEventHandler;

    #[async_trait]
    impl EventHandler for ErroringEventHandler {
        async fn handle_event(&self, _event: &Event) -> Result<(), EventError> {
            Err(EventError::BusError("Test error".into()))
        }
    }

    struct TestPublisher {
        calls: Arc<AtomicUsize>,
        fail: bool,
    }

    #[async_trait]
    impl EventPublisher for TestPublisher {
        async fn publish(&self, _envelope: &EventEnvelope) -> Result<(), EventError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(EventError::BusError("publisher failure".into()))
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn test_event_bus_empty() {
        let event_bus = EventBus::default();
        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // Should succeed with no handlers
        event_bus
            .emit(&Event::UserCreated(test_user))
            .await
            .expect("Failed to emit event");
    }

    #[tokio::test]
    async fn test_event_bus_multiple_handlers() {
        let event_bus = EventBus::default();
        let called1 = Arc::new(AtomicBool::new(false));
        let count1 = Arc::new(AtomicUsize::new(0));
        let called2 = Arc::new(AtomicBool::new(false));
        let count2 = Arc::new(AtomicUsize::new(0));

        let handler1 = TestEventHandler {
            called: called1.clone(),
            call_count: count1.clone(),
        };
        let handler2 = TestEventHandler {
            called: called2.clone(),
            call_count: count2.clone(),
        };

        event_bus.register(Arc::new(handler1)).await;
        event_bus.register(Arc::new(handler2)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // Both handlers should be called
        event_bus
            .emit(&Event::UserCreated(test_user))
            .await
            .expect("Failed to emit event");

        assert!(
            called1.load(Ordering::SeqCst),
            "First handler was not called"
        );
        assert!(
            called2.load(Ordering::SeqCst),
            "Second handler was not called"
        );
        assert_eq!(count1.load(Ordering::SeqCst), 1);
        assert_eq!(count2.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_event_bus_handler_errors_are_best_effort() {
        let event_bus = EventBus::default();
        event_bus.register(Arc::new(ErroringEventHandler)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        // A handler failure must not turn event publication into an operation failure.
        let result = event_bus.emit(&Event::UserCreated(test_user)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn publishers_receive_emitted_events() {
        let event_bus = EventBus::default();
        let calls = Arc::new(AtomicUsize::new(0));
        event_bus
            .register_publisher(Arc::new(TestPublisher {
                calls: calls.clone(),
                fail: false,
            }))
            .await;

        let user = User::builder()
            .id(UserId::new("publisher-test"))
            .email("publisher@example.com".to_string())
            .build()
            .expect("Failed to build test user");
        event_bus.emit(&Event::UserCreated(user)).await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn publisher_errors_are_best_effort() {
        let event_bus = EventBus::default();
        let calls = Arc::new(AtomicUsize::new(0));
        event_bus
            .register_publisher(Arc::new(TestPublisher {
                calls: calls.clone(),
                fail: true,
            }))
            .await;

        let user = User::builder()
            .id(UserId::new("publisher-error-test"))
            .email("publisher-error@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        assert!(event_bus.emit(&Event::UserCreated(user)).await.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_event_bus_all_event_types() {
        let event_bus = EventBus::default();
        let called = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));

        let handler = TestEventHandler {
            called: called.clone(),
            call_count: count.clone(),
        };
        event_bus.register(Arc::new(handler)).await;

        let test_user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        let test_session = Session::builder()
            .token(SessionToken::new("test"))
            .user_id(test_user.id.clone())
            .build()
            .expect("Failed to build test session");

        // Test all event types
        let events = vec![
            Event::UserCreated(test_user.clone()),
            Event::UserUpdated(test_user.clone()),
            Event::UserDeleted(test_user.id.clone()),
            Event::SessionCreated(test_user.id.clone(), test_session.clone()),
            Event::SessionDeleted(
                test_user.id.clone(),
                test_session.token.clone().expect("token should be present"),
            ),
            Event::SessionsCleared(test_user.id.clone()),
            Event::SessionRefreshed(test_user.id.clone(), test_session.clone()),
            Event::PasswordRegistered(test_user.id.clone()),
            Event::PasswordAuthenticated(test_user.id.clone()),
            Event::PasswordChanged(test_user.id.clone()),
            Event::PasswordRemoved(test_user.id.clone()),
            Event::PasswordResetRequested(test_user.id.clone()),
            Event::PasswordResetCompleted(test_user.id.clone()),
            Event::OAuthAuthenticated {
                user_id: test_user.id.clone(),
                provider: "test".to_string(),
            },
            Event::OAuthAccountLinked {
                user_id: test_user.id.clone(),
                provider: "test".to_string(),
            },
            Event::OAuthAccountUnlinked {
                user_id: test_user.id.clone(),
                provider: "test".to_string(),
            },
            Event::PasskeyRegistered(test_user.id.clone()),
            Event::PasskeyAuthenticated(test_user.id.clone()),
            Event::PasskeyRemoved(test_user.id.clone()),
            Event::MagicLinkRequested(test_user.id.clone()),
            Event::MagicLinkAuthenticated(test_user.id.clone()),
            Event::EmailVerificationRequested(test_user.id.clone()),
            Event::EmailVerified(test_user.id.clone()),
            Event::LoginFailed {
                email: test_user.email.clone(),
                failed_attempts: 1,
                ip_address: None,
                timestamp: chrono::Utc::now(),
            },
            Event::AccountLocked {
                email: test_user.email.clone(),
                failed_attempts: 5,
                locked_until: chrono::Utc::now(),
                ip_address: None,
                timestamp: chrono::Utc::now(),
            },
            Event::AccountUnlocked {
                email: test_user.email.clone(),
                reason: torii_core::events::UnlockReason::PasswordReset,
                timestamp: chrono::Utc::now(),
            },
        ];

        let expected_count = events.len();
        for event in events {
            called.store(false, Ordering::SeqCst);
            event_bus.emit(&event).await.expect("Failed to emit event");
            assert!(called.load(Ordering::SeqCst), "Handler was not called");
        }

        assert_eq!(count.load(Ordering::SeqCst), expected_count);
    }

    #[tokio::test]
    async fn remote_dispatch_ignores_events_from_this_replica() {
        let event_bus = EventBus::default();
        let called = Arc::new(AtomicBool::new(false));
        event_bus
            .register(Arc::new(TestEventHandler {
                called: called.clone(),
                call_count: Arc::new(AtomicUsize::new(0)),
            }))
            .await;

        let user = User::builder()
            .id(UserId::new("test"))
            .email("test@example.com".to_string())
            .build()
            .expect("Failed to build test user");

        event_bus
            .dispatch_remote(&event_bus.envelope(Event::UserCreated(user)))
            .await
            .expect("Failed to dispatch event");

        assert!(!called.load(Ordering::SeqCst));
    }
}
