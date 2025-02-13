# RFC 0003: MongoDB Storage Provider

**Status**: Draft - Not thoroughly reviewed

## Summary

Add MongoDB as a storage provider for Torii, enabling users to store authentication data in MongoDB while maintaining the same storage interface defined in [RFC 0002](./002-plugin-interfaces.md).

## Motivation

MongoDB offers several advantages as a storage backend:

1. **Schema Flexibility**: Easier to evolve data models over time
2. **Horizontal Scalability**: Built-in sharding and replication
3. **Rich Indexing**: Support for TTL, compound, and geospatial indexes
4. **Cloud Native**: First-class support in major cloud providers
5. **Document Model**: Natural fit for user and session data

## Design

### Storage Models

```rust
#[derive(Serialize, Deserialize)]
pub struct MongoUser {
    #[serde(rename = "_id")]
    pub id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified_at: Option<DateTime>,
    pub created_at: DateTime,
    pub updated_at: DateTime,
    #[serde(default)]
    pub metadata: Document, // Flexible metadata storage
}

#[derive(Serialize, Deserialize)]
pub struct MongoSession {
    #[serde(rename = "_id")]
    pub id: String,
    pub user_id: String,
    pub expires_at: DateTime,
    pub created_at: DateTime,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
}
```

### Storage Implementation

```rust
pub struct MongoStorage {
    client: Client,
    database: String,
}

#[derive(Clone)]
pub struct MongoHandle {
    db: Database,
    users: Collection<MongoUser>,
    sessions: Collection<MongoSession>,
}

#[async_trait]
impl StoragePlugin for MongoStorage {
    type Config = MongoConfig;
    type Handle = MongoHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        let db = self.client.database(&self.database);

        // Create collections
        let users = db.collection("users");
        let sessions = db.collection("sessions");

        // Setup indexes
        self.setup_indexes(&users, &sessions).await?;

        Ok(MongoHandle { db, users, sessions })
    }
}
```

### Indexes

```rust
impl MongoStorage {
    async fn setup_indexes(
        &self,
        users: &Collection<MongoUser>,
        sessions: &Collection<MongoSession>,
    ) -> Result<(), Error> {
        // User indexes
        users.create_index(
            IndexModel::builder()
                .keys(doc! { "email": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
            None,
        ).await?;

        // Session indexes
        sessions.create_index(
            IndexModel::builder()
                .keys(doc! { "expires_at": 1 })
                .options(IndexOptions::builder()
                    .expire_after(Duration::ZERO)
                    .build())
                .build(),
            None,
        ).await?;

        sessions.create_index(
            IndexModel::builder()
                .keys(doc! { "user_id": 1 })
                .build(),
            None,
        ).await?;

        Ok(())
    }
}
```

### Configuration

```rust
#[derive(Debug, Clone)]
pub struct MongoConfig {
    pub uri: String,
    pub database: String,
    pub max_pool_size: Option<u32>,
    pub min_pool_size: Option<u32>,
    pub timeout: Option<Duration>,
}

impl Default for MongoConfig {
    fn default() -> Self {
        Self {
            uri: "mongodb://localhost:27017".to_string(),
            database: "torii".to_string(),
            max_pool_size: Some(10),
            min_pool_size: Some(1),
            timeout: Some(Duration::from_secs(30)),
        }
    }
}
```

## Implementation Details

### 1. Connection Management

- Use connection pooling for efficient resource usage
- Support replica set configuration
- Handle connection failures gracefully
- Support TLS/SSL connections

### 2. Data Migration

```rust
impl MongoStorage {
    pub async fn migrate(&self) -> Result<(), Error> {
        // Version collection for tracking migrations
        let versions = self.db.collection("versions");

        // Run migrations in order
        self.migrate_v1().await?;
        self.migrate_v2().await?;

        Ok(())
    }
}
```

### 3. Error Mapping

```rust
impl From<mongodb::error::Error> for Error {
    fn from(err: mongodb::error::Error) -> Self {
        match err.kind.as_ref() {
            ErrorKind::Write(WriteFailure::WriteError(e))
                if e.code == 11000 => Error::Duplicate,
            ErrorKind::Authentication => Error::Authentication,
            _ => Error::Storage(err.to_string()),
        }
    }
}
```

### 4. Transactions

```rust
impl MongoHandle {
    pub async fn transaction<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&MongoHandle) -> Future<Output = Result<T, Error>>,
    {
        let session = self.client.start_session().await?;
        session.start_transaction().await?;

        match f(self).await {
            Ok(result) => {
                session.commit_transaction().await?;
                Ok(result)
            }
            Err(e) => {
                session.abort_transaction().await?;
                Err(e)
            }
        }
    }
}
```

## Benefits

1. **Scalability**: Native support for horizontal scaling
2. **Flexibility**: Schema-less design for future extensions
3. **Performance**: Efficient indexing and query capabilities
4. **Operations**: Built-in monitoring and management tools
5. **Cloud Support**: Easy deployment to major cloud providers

## Migration Guide

1. **Install Dependencies**:

```toml
[dependencies]
mongodb = "2.8"
```

2. **Configure Storage**:

```rust
let config = MongoConfig {
    uri: "mongodb://localhost:27017",
    database: "torii",
    ..Default::default()
};

let storage = MongoStorage::new(config)?;
```

3. **Data Migration**:

```bash
# Export from SQLite
sqlite3 torii.db .dump > dump.sql

# Import to MongoDB
torii migrate --from sqlite --to mongodb
```

## Questions

1. Should we support MongoDB-specific features like Change Streams?
2. How should we handle schema evolution?
3. Should we support MongoDB Atlas-specific features?
4. How do we handle connection pooling in serverless environments?

## Alternatives Considered

1. **Use ODM Layer**

   - More abstraction
   - Higher overhead
   - Less flexible queries

2. **Raw BSON Documents**

   - More flexible
   - Less type safety
   - More error-prone

3. **Hybrid Approach**
   - Use typed models for core fields
   - Raw BSON for extensible fields
   - Balance of safety and flexibility

## References

- [MongoDB Rust Driver](https://docs.rs/mongodb)
- [MongoDB Index Types](https://www.mongodb.com/docs/manual/indexes/)
- [MongoDB Transactions](https://www.mongodb.com/docs/manual/core/transactions/)
- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)
