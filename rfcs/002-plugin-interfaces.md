# RFC 002: Separate Core Plugin Interfaces

| Date       | Author       | Status         |
| ---------- | ------------ | -------------- |
| 2025-02-19 | @cmackenzie1 | ✅ Implemented |

## Summary

Split the plugin system into specialized interfaces to improve modularity, type safety, and maintainability. Each interface has a focused responsibility:

1. `AuthPlugin` - Core authentication functionality
2. `StoragePlugin` - Data persistence operations
3. `EventHandler` - Event processing capabilities
4. `EmailPasswordStorage` - Email/password specific storage operations
5. `OAuthStorage` - OAuth specific storage operations

## Motivation

A single monolithic plugin interface forces plugins to implement functionality they don't need, leading to:

1. **Unnecessary Implementation Burden**: Plugins must implement unused methods
2. **Poor Type Safety**: No compile-time guarantees about plugin capabilities
3. **Testing Complexity**: Mocking requires implementing unused methods
4. **Limited Flexibility**: Difficult to compose plugin functionality

## Design

### Core Interfaces

```rust
#[async_trait]
pub trait AuthPlugin: Plugin + Send + Sync + 'static + DowncastSync {
    /// Unique identifier for this auth method
    fn auth_method(&self) -> &str;

    /// Authenticate a user and create a session
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResponse, Error>;

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
    /// Handle plugin events
    async fn handle_event(&self, event: &Event) -> Result<(), Error>;
}

#[async_trait]
pub trait EmailPasswordStorage: UserStorage {
    /// Store a password hash for a user
    async fn set_password_hash(&self, user_id: &UserId, hash: &str) -> Result<(), Self::Error>;

    /// Retrieve a user's password hash
    async fn get_password_hash(&self, user_id: &UserId) -> Result<Option<String>, Self::Error>;
}

#[async_trait]
pub trait OAuthStorage: UserStorage {
    /// Create a new OAuth account linked to a user
    async fn create_oauth_account(
        &self,
        provider: &str,
        subject: &str,
        user_id: &UserId,
    ) -> Result<OAuthAccount, Self::Error>;

    /// Find a user by their OAuth provider and subject
    async fn get_user_by_provider_and_subject(
        &self,
        provider: &str,
        subject: &str,
    ) -> Result<Option<User>, Self::Error>;
}
```

### Plugin Registration

```rust
pub struct PluginManager<U: UserStorage, S: SessionStorage> {
    auth_plugins: DashMap<String, Arc<dyn AuthPlugin>>,
    storage: Storage<U, S>,
}

impl<U: UserStorage, S: SessionStorage> PluginManager<U, S> {
    pub fn register_auth_plugin<T: AuthPlugin + 'static>(&mut self, plugin: T) {
        self.auth_plugins.insert(plugin.name().to_string(), Arc::new(plugin));
    }

    pub fn storage(&self) -> &Storage<U, S> {
        &self.storage
    }
}
```

## Benefits

1. **Clear Responsibilities**: Each interface has a focused set of related functionality
2. **Type Safety**: Compile-time verification of plugin capabilities
3. **Easier Testing**: Mock only the interfaces you need
4. **Flexible Composition**: Plugins can implement multiple interfaces as needed
5. **Future Extensibility**: New plugin types can be added without affecting existing ones

## References

- [RFC 0001: Plugin Event System](./001-plugin-events.md)
