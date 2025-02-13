# RFC 0006: Redis/ValKey Storage Provider

**Status**: Draft - Not thoroughly reviewed

## Summary

Add Redis support as a caching and session storage layer for Torii, with optional support for ValKey as a Redis-compatible alternative. This implementation will focus on high-performance session management and caching while maintaining compatibility with the storage interface defined in RFC 0002.

## Motivation

Redis/ValKey offers several advantages for session and cache storage:

1. **Performance**: In-memory storage with sub-millisecond response times
2. **TTL Support**: Native expiration for sessions and cache entries
3. **Scalability**: Cluster support for horizontal scaling
4. **Persistence**: Optional durability with AOF/RDB
5. **Atomic Operations**: Built-in support for atomic operations
6. **Compatibility**: ValKey provides Redis compatibility with Rust implementation

## Design

### Storage Models

```rust
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CachedUser {
    #[serde(flatten)]
    pub user: User,
    #[serde(with = "time::serde::timestamp")]
    pub cached_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CachedSession {
    #[serde(flatten)]
    pub session: Session,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RedisConfig {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database: i32,
    pub cluster_mode: bool,
    pub tls_enabled: bool,
    pub key_prefix: String,
    pub pool_size: usize,
    pub cache_ttl: Duration,
}

pub struct RedisStorage {
    client: redis::Client,
    config: RedisConfig,
}

#[derive(Clone)]
pub struct RedisHandle {
    pool: redis::aio::ConnectionManager,
    config: RedisConfig,
}
```

### Storage Implementation

```rust
#[async_trait]
impl StoragePlugin for RedisStorage {
    type Config = RedisConfig;
    type Handle = RedisHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        let pool = self.client.get_connection_manager().await?;

        // Test connection
        let mut conn = pool.clone();
        redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(Error::from)?;

        Ok(RedisHandle { pool, config })
    }
}

impl RedisHandle {
    fn key(&self, kind: &str, id: &str) -> String {
        format!("{}:{}:{}", self.config.key_prefix, kind, id)
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        key: &str
    ) -> Result<Option<T>, Error> {
        let mut conn = self.pool.clone();
        let data: Option<String> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await?;

        match data {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn set_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> Result<(), Error> {
        let json = serde_json::to_string(value)?;
        let mut conn = self.pool.clone();

        match ttl {
            Some(ttl) => {
                redis::cmd("SETEX")
                    .arg(key)
                    .arg(ttl.as_secs())
                    .arg(json)
                    .query_async(&mut conn)
                    .await?
            }
            None => {
                redis::cmd("SET")
                    .arg(key)
                    .arg(json)
                    .query_async(&mut conn)
                    .await?
            }
        }

        Ok(())
    }
}
```
