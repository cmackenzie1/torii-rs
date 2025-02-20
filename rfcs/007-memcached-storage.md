# RFC 007: Memcached Storage Provider

| Date       | Author       | Status   |
| ---------- | ------------ | -------- |
| 2025-02-19 | @cmackenzie1 | 📝 Draft |

## Summary

Add Memcached support as a caching layer for Torii, focusing on distributed caching for user sessions and frequently accessed data. This implementation will provide a simpler alternative to Redis/ValKey while maintaining compatibility with the storage interface defined in RFC 0002.

## Motivation

Memcached offers several advantages as a caching layer:

1. **Simplicity**: Simple key-value protocol with minimal complexity
2. **Performance**: High throughput and low latency
3. **Memory Management**: Efficient LRU eviction
4. **Distribution**: Simple horizontal scaling
5. **Proven**: Battle-tested in large-scale deployments

## Design

### Storage Models

```rust
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone)]
pub struct MemcachedConfig {
    pub nodes: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub timeout: Duration,
    pub tcp_nodelay: bool,
    pub tcp_keepalive: Option<Duration>,
    pub pool_size: usize,
    pub default_ttl: Duration,
}

pub struct MemcachedStorage {
    client: memcache::Client,
    config: MemcachedConfig,
}

#[derive(Clone)]
pub struct MemcachedHandle {
    client: memcache::Client,
    config: MemcachedConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry<T> {
    data: T,
    #[serde(with = "time::serde::timestamp")]
    cached_at: DateTime<Utc>,
    version: u64,
}
```

### Storage Implementation

```rust
#[async_trait]
impl StoragePlugin for MemcachedStorage {
    type Config = MemcachedConfig;
    type Handle = MemcachedHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        // Test connection to all nodes
        for node in &config.nodes {
            let mut conn = self.client.get_connection(node)?;
            conn.version()
                .await
                .map_err(|e| Error::Storage(format!("Failed to connect to {}: {}", node, e)))?;
        }

        Ok(MemcachedHandle {
            client: self.client.clone(),
            config,
        })
    }
}

impl MemcachedHandle {
    fn key(&self, namespace: &str, id: &str) -> String {
        format!("torii:{}:{}", namespace, id)
    }

    async fn get_value<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, Error> {
        match self.client.get(key).await? {
            Some(data) => {
                let entry: CacheEntry<T> = bincode::deserialize(&data)?;
                Ok(Some(entry.data))
            }
            None => Ok(None),
        }
    }

    async fn set_value<T: Serialize>(
        &self,
        key: &str,
        value: T,
        ttl: Option<Duration>,
    ) -> Result<(), Error> {
        let entry = CacheEntry {
            data: value,
            cached_at: Utc::now(),
            version: 1,
        };

        let data = bincode::serialize(&entry)?;
        self.client
            .set(key, data, ttl.unwrap_or(self.config.default_ttl))
            .await?;

        Ok(())
    }

    async fn delete_value(&self, key: &str) -> Result<(), Error> {
        self.client.delete(key).await?;
        Ok(())
    }
}
```

### Session Storage Implementation

```rust
#[async_trait]
impl SessionStorage for MemcachedHandle {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        let key = self.key("session", &session.id.to_string());
        let ttl = session.expires_at - Utc::now();

        self.set_value(&key, session, Some(ttl.to_std()?))
            .await?;

        Ok(session.clone())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Option<Session>, Error> {
        let key = self.key("session", &id.to_string());
        self.get_value(&key).await
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), Error> {
        let key = self.key("session", &id.to_string());
        self.delete_value(&key).await
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        // Memcached handles expiration automatically
        Ok(())
    }
}
```

### User Cache Implementation

```rust
impl MemcachedHandle {
    pub async fn cache_user(&self, user: &User) -> Result<(), Error> {
        let key = self.key("user", &user.id.to_string());
        self.set_value(&key, user, Some(self.config.default_ttl))
            .await
    }

    pub async fn get_cached_user(&self, id: &UserId) -> Result<Option<User>, Error> {
        let key = self.key("user", &id.to_string());
        self.get_value(&key).await
    }

    pub async fn invalidate_user(&self, id: &UserId) -> Result<(), Error> {
        let key = self.key("user", &id.to_string());
        self.delete_value(&key).await
    }
}
```

### Consistent Hashing

```rust
use std::hash::{Hash, Hasher};
use siphasher::sip::SipHasher;

impl MemcachedHandle {
    fn get_node_for_key(&self, key: &str) -> &str {
        let mut hasher = SipHasher::new();
        key.hash(&mut hasher);
        let hash = hasher.finish();

        let nodes = &self.config.nodes;
        let index = (hash % nodes.len() as u64) as usize;
        &nodes[index]
    }

    async fn with_node<F, T>(&self, key: &str, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut memcache::Connection) -> Future<Output = Result<T, memcache::Error>>,
    {
        let node = self.get_node_for_key(key);
        let mut conn = self.client.get_connection(node)?;
        f(&mut conn).await.map_err(Error::from)
    }
}
```

## Features

### 1. Binary Protocol Support

```rust
impl MemcachedStorage {
    pub fn with_binary_protocol(config: MemcachedConfig) -> Result<Self, Error> {
        let client = memcache::Client::connect(config.nodes.clone())
            .with_protocol(memcache::Protocol::Binary)?;

        Ok(Self { client, config })
    }
}
```

### 2. Connection Pooling

```rust
use deadpool::managed::{Manager, Pool};

#[derive(Clone)]
struct MemcachedConnectionManager {
    nodes: Vec<String>,
}

impl Manager for MemcachedConnectionManager {
    type Type = memcache::Connection;
    type Error = memcache::Error;

    async fn create(&self) -> Result<Self::Type, Self::Error> {
        // Round-robin connection creation
        let node = &self.nodes[thread_rng().gen_range(0..self.nodes.len())];
        memcache::Client::connect(node).await
    }

    async fn recycle(
        &self,
        conn: &mut Self::Type,
    ) -> deadpool::managed::RecycleResult<Self::Error> {
        match conn.version().await {
            Ok(_) => Ok(()),
            Err(_) => Err(deadpool::managed::RecycleError::Message(
                "Connection health check failed".into(),
            )),
        }
    }
}
```

## Benefits

1. **Simplicity**: Simple protocol and architecture
2. **Performance**: Fast key-value operations
3. **Memory Efficiency**: Automatic LRU eviction
4. **Distribution**: Built-in consistent hashing
5. **Resource Usage**: Low memory overhead

## Migration Guide

1. **Install Dependencies**:

```toml
[dependencies]
memcache = { version = "0.17", features = ["async"] }
deadpool = { version = "0.9", features = ["managed"] }
```

2. **Configure Storage**:

```rust
let config = MemcachedConfig {
    nodes: vec!["localhost:11211".to_string()],
    username: None,
    password: None,
    timeout: Duration::from_secs(1),
    tcp_nodelay: true,
    tcp_keepalive: Some(Duration::from_secs(60)),
    pool_size: 10,
    default_ttl: Duration::from_secs(3600),
};

let storage = MemcachedStorage::new(config)?;
```

## Memcached vs Redis Comparison

### Memcached Advantages

- Simpler protocol
- Lower memory overhead
- Better multi-threaded performance
- Automatic LRU eviction

### Memcached Limitations

- No persistence
- No complex data types
- No pub/sub
- No transactions

## Questions

1. Should we support SASL authentication?
2. How should we handle node failures?
3. What compression strategies should we use?
4. Should we implement client-side sharding?

## Alternatives Considered

1. **Local Cache**

   - No additional infrastructure
   - No distribution
   - Limited capacity

2. **Redis Only**

   - More features
   - Higher complexity
   - More resource intensive

3. **Hybrid Approach**
   - Local cache + Memcached
   - More complex implementation
   - Better performance

## References

- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)
- [RFC 0006: Redis Storage](./006-redis-storage.md)
- [Memcached Protocol](https://github.com/memcached/memcached/blob/master/doc/protocol.txt)
- [Consistent Hashing](https://www.last.fm/user/RJ/journal/2007/04/10/rz_libketama_-_a_consistent_hashing_algo_for_memcache_clients)
