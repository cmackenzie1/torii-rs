# RFC 0001: Plugin Event System

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

```rust
pub enum PluginEvent {
    UserCreated {
        user: User,
        source: String,
    },
    UserAuthenticated {
        user: User,
        session: Session,
        source: String,
    },
    UserDeleted {
        user_id: UserId,
        source: String,
    },
    SessionCreated {
        session: Session,
        source: String,
    },
    SessionRevoked {
        session_id: String,
        source: String,
    },
}
```

### Event Handler Trait

```rust
#[async_trait]
pub trait EventHandler: Send + Sync {
    async fn handle_event(&self, event: PluginEvent) -> Result<(), Error>;
}
```

### Plugin Trait Extension

The `Plugin` trait will be extended to include event handling capabilities:

```rust
#[async_trait]
pub trait Plugin<U: UserStorage, S: SessionStorage>: EventHandler + Any + Send + Sync + DowncastSync {
    // Existing methods...

    async fn emit_event(&self, manager: &PluginManager<U, S>, event: PluginEvent)
        -> Result<(), Error>;
}
```

## Examples

### Email Password Plugin

```rust
impl EmailPasswordPlugin {
    pub async fn login_user(...) -> Result<(User, Session), Error> {
        // ... login logic ...

        self.emit_event(
            manager,
            PluginEvent::UserAuthenticated {
                user: user.clone(),
                session: session.clone(),
                source: self.name().to_string(),
            },
        ).await?;

        Ok((user, session))
    }
}
```

### OIDC Plugin

```rust
impl EventHandler for OIDCPlugin {
    async fn handle_event(&self, event: PluginEvent) -> Result<(), Error> {
        match event {
            PluginEvent::UserAuthenticated { user, source, .. } => {
                if source != self.name() {
                    tracing::info!("User {} authenticated via {}", user.email, source);
                    // Opportunity to link accounts or update records
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}
```

## Benefits

1. **Loose Coupling**: Plugins can interact without direct dependencies
2. **Extensibility**: New events can be added without breaking existing plugins
3. **Observability**: Easy to monitor and log inter-plugin interactions
4. **Flexibility**: Plugins can choose which events to handle
5. **Async Support**: All event handling is async-compatible

## Use Cases

1. **Account Linking**

   - Link OIDC accounts with email accounts
   - Merge user data from different auth methods

2. **Audit Logging**

   - Track authentication events across plugins
   - Monitor security-relevant actions

3. **Data Consistency**

   - Clean up plugin-specific data when users are deleted
   - Synchronize user data across plugins

4. **Analytics**
   - Track authentication patterns
   - Monitor plugin usage

## Implementation Notes

1. Events are broadcast to all plugins
2. Event handling errors are collected and reported
3. Events include source plugin information
4. All event handling is asynchronous
5. Events are cloneable and serializable

## Future Considerations

1. Event filtering/routing
2. Event persistence
3. Event replay capabilities
4. Plugin-specific event types
5. Event versioning

## Questions

1. Should events be persisted?
2. How to handle event versioning?
3. Should plugins be able to cancel/modify events?
4. How to handle event ordering?

## Alternatives Considered

1. **Direct Plugin Communication**

   - More tightly coupled
   - More difficult to maintain
   - Less flexible

2. **Shared State**

   - More complex
   - Potential race conditions
   - Less clear ownership

3. **No Inter-plugin Communication**
   - Limited functionality
   - Duplicate implementation
   - Poor user experience

## References

- [Event Sourcing Pattern](https://martinfowler.com/eaaDev/EventSourcing.html)
- [Observer Pattern](https://en.wikipedia.org/wiki/Observer_pattern)
- [Pub/Sub Pattern](https://en.wikipedia.org/wiki/Publish%E2%80%93subscribe_pattern)
