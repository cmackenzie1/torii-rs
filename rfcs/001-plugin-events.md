# RFC 001: Plugin Event System

| Date       | Author       | Status         |
| ---------- | ------------ | -------------- |
| 2025-02-19 | @cmackenzie1 | ✅ Implemented |

## Summary

Add an event system to enable loose coupling between plugins while allowing them to react to actions performed by other plugins.

## Motivation

Currently, plugins operate in isolation and have no way to coordinate or react to actions performed by other plugins. An event system would allow plugins to:

- Respond to actions from other plugins (e.g, index users in a search index)
- Maintain plugin-specific data consistency
- Enable cross-plugin features like account linking
- Facilitate audit logging and monitoring

## Design

### Event Types

The following events are currently implemented:

```rust
pub enum Event {
    UserCreated(User),
    UserUpdated(User),
    UserDeleted(UserId),
    SessionCreated(UserId, Session),
    SessionDeleted(UserId, SessionId),
}
```

### Event Handler Trait

```rust
#[async_trait]
pub trait EventHandler: Send + Sync + 'static {
    async fn handle_event(&self, event: &Event) -> Result<(), Error>;
}
```

### Event Bus

The event bus manages event handlers and event distribution:

```rust
pub struct EventBus {
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
}

impl EventBus {
    pub fn new() -> Self;
    pub async fn register(&self, handler: Arc<dyn EventHandler>);
    pub async fn emit(&self, event: &Event) -> Result<(), Error>;
}
```

## Examples

### Implementing an Event Handler

```rust
struct MyHandler;

#[async_trait]
impl EventHandler for MyHandler {
    async fn handle_event(&self, event: &Event) -> Result<(), Error> {
        match event {
            Event::UserCreated(user) => {
                // Handle user creation
                Ok(())
            }
            // Handle other events...
            _ => Ok(()),
        }
    }
}

// Register the handler
let event_bus = EventBus::new();
event_bus.register(Arc::new(MyHandler)).await;
```

### Emitting Events

```rust
let event_bus = EventBus::new();
let user = User::builder()
    .id(UserId::new("test"))
    .email("test@example.com")
    .build()?;

event_bus.emit(&Event::UserCreated(user)).await?;
```

## Benefits

1. **Loose Coupling**: Plugins can interact without direct dependencies
2. **Extensibility**: New events can be added without breaking existing plugins
3. **Observability**: Easy to monitor and log inter-plugin interactions
4. **Flexibility**: Plugins can choose which events to handle
5. **Async Support**: All event handling is async-compatible
6. **Thread Safety**: Event bus is thread-safe using `Arc` and `RwLock`

### Current Features

- User lifecycle events (created, updated, deleted)
- Session lifecycle events (created, deleted)
- Async event handling
- Error propagation
- Thread-safe handler management

### Known Limitations

1. Events are not currently persisted
2. No event filtering mechanism
3. Events are processed sequentially
4. No replay capability
5. No way to unregister handlers

## Future Work

1. Add event persistence layer
2. Implement event filtering
3. Add parallel event processing
4. Support event replay for recovery
5. Add handler unregistration
6. Consider adding more granular events
7. Add event metadata (timestamp, correlation ID)

## Questions

1. Should events be persisted?
2. How to handle event versioning?
3. Should we add handler priorities?
4. How to handle event ordering?
5. Should we add handler unregistration?

## References

- [Event Sourcing Pattern](https://martinfowler.com/eaaDev/EventSourcing.html)
- [Observer Pattern](https://en.wikipedia.org/wiki/Observer_pattern)
- [Pub/Sub Pattern](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern)
