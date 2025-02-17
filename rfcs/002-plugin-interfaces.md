# RFC 0002: Separate Core Plugin Interfaces

**Status**: Implemented

## Summary

Split the monolithic `Plugin` trait into specialized interfaces to improve modularity, type safety, and maintainability of the plugin system.

## Motivation

The current plugin system uses a single `Plugin` trait that forces all plugins to implement functionality they may not need. This creates several issues:

1. **Unnecessary Implementation Burden**: Plugins must implement methods they don't use
2. **Poor Type Safety**: No compile-time guarantees about plugin capabilities
3. **Testing Complexity**: Mocking requires implementing unused methods
4. **Limited Flexibility**: Difficult to compose plugin functionality

## Design

### Core Interfaces

```rust
#[async_trait]
pub trait AuthPlugin: Send + Sync + 'static {
    /// Unique identifier for this auth method
    fn auth_method(&self) -> &str;

    /// Authenticate a user and create a session
    async fn authenticate(&self, credentials: &Credentials) -> Result<(User, Session), Error>;

    /// Validate an existing session
    async fn validate_session(&self, session: &Session) -> Result<bool, Error>;

    /// Handle logout/session termination
    async fn logout(&self, session: &Session) -> Result<(), Error>;
}

#[async_trait]
pub trait StoragePlugin: Send + Sync + 'static {
    type Config;

    /// Initialize storage with config
    async fn initialize(&self, config: Self::Config) -> Result<(), Error>;

    /// Storage health check
    async fn health_check(&self) -> Result<(), Error>;

    /// Clean up expired data
    async fn cleanup(&self) -> Result<(), Error>;
}

#[async_trait]
pub trait EventHandler: Send + Sync + 'static {
    /// Handle plugin events as defined in RFC 0001
    async fn handle_event(&self, event: PluginEvent) -> Result<(), Error>;
}
```

### Plugin Registration

```rust
pub struct PluginManager {
    auth_plugins: HashMap<String, Box<dyn AuthPlugin>>,
    storage_plugins: HashMap<String, Box<dyn StoragePlugin>>,
    event_handlers: Vec<Box<dyn EventHandler>>,
}

impl PluginManager {
    pub fn register_auth(&mut self, plugin: impl AuthPlugin) {
        self.auth_plugins.insert(plugin.auth_method().to_string(), Box::new(plugin));
    }

    pub fn register_storage(&mut self, name: &str, plugin: impl StoragePlugin) {
        self.storage_plugins.insert(name.to_string(), Box::new(plugin));
    }

    pub fn register_event_handler(&mut self, handler: impl EventHandler) {
        self.event_handlers.push(Box::new(handler));
    }
}
```

## Examples

### Email Password Plugin

```rust
pub struct EmailPasswordPlugin {
    // ... fields ...
}

#[async_trait]
impl AuthPlugin for EmailPasswordPlugin {
    fn auth_method(&self) -> &str {
        "email_password"
    }

    async fn authenticate(&self, credentials: &Credentials) -> Result<(User, Session), Error> {
        // Implementation
    }
}

#[async_trait]
impl EventHandler for EmailPasswordPlugin {
    async fn handle_event(&self, event: PluginEvent) -> Result<(), Error> {
        // Handle relevant events
    }
}
```

### SQLite Storage Plugin

```rust
pub struct SqliteStorage {
    // ... fields ...
}

#[async_trait]
impl StoragePlugin for SqliteStorage {
    type Config = SqliteConfig;

    async fn initialize(&self, config: Self::Config) -> Result<(), Error> {
        // Implementation
    }
}
```

## Benefits

1. **Clear Responsibilities**: Each interface has a focused set of related functionality
2. **Type Safety**: Compile-time verification of plugin capabilities
3. **Easier Testing**: Mock only the interfaces you need
4. **Flexible Composition**: Plugins can implement multiple interfaces as needed
5. **Future Extensibility**: New plugin types can be added without affecting existing ones

## Migration Strategy

1. **Phase 1**: Introduce new interfaces alongside existing `Plugin` trait
2. **Phase 2**: Update existing plugins to implement new interfaces
3. **Phase 3**: Deprecate monolithic `Plugin` trait
4. **Phase 4**: Remove old `Plugin` trait in next major version

## Compatibility

This change is breaking and requires a major version bump. However, the migration can be done gradually by:

1. Keeping the old `Plugin` trait temporarily
2. Providing adapter traits to bridge old and new interfaces
3. Updating documentation with migration examples

## Questions

1. Should we allow plugins to dynamically expose interfaces?
2. How should we handle interface versioning?
3. Should we provide default implementations for some methods?
4. How do we handle cross-cutting concerns like logging?

## Alternatives Considered

1. **Trait Objects with Dynamic Dispatch**

   - More runtime overhead
   - Less type safety
   - More flexible at runtime

2. **Enum-based Plugin Types**

   - Less flexible
   - More rigid boundaries
   - Simpler implementation

3. **Keep Single Plugin Trait**
   - Familiar
   - Less maintenance
   - Continued issues with current design

## References

- [RFC 0001: Plugin Event System](./001-plugin-events.md)
- [Rust Trait Objects](https://doc.rust-lang.org/book/ch17-02-trait-objects.html)
- [Interface Segregation Principle](https://en.wikipedia.org/wiki/Interface_segregation_principle)
