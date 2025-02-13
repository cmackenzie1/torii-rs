# RFC 0005: MySQL Storage Provider

**Status**: Draft - Not thoroughly reviewed

## Summary

Add MySQL as a storage provider for Torii, implementing the storage interface defined in RFC 0002 while leveraging MySQL-specific features and optimizations.

## Motivation

MySQL offers several advantages as a storage backend:

1. **Wide Adoption**: Extensive community support and tooling
2. **Performance**: Optimized for high-throughput OLTP workloads
3. **Replication**: Built-in primary-replica configuration
4. **Cloud Support**: First-class support in major cloud platforms
5. **Resource Efficiency**: Lower memory footprint compared to PostgreSQL

## Design

### Database Schema

```sql
-- Enable strict mode and UTF8MB4 encoding
SET sql_mode = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION';
SET NAMES utf8mb4;
SET CHARACTER SET utf8mb4;

-- Core schema for users and sessions
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    email_verified_at DATETIME(6),
    metadata JSON,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE sessions (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    user_agent VARCHAR(255),
    ip_address VARCHAR(45),
    metadata JSON,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_expires_at (expires_at),
    FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Event for cleaning up expired sessions
CREATE EVENT cleanup_expired_sessions
    ON SCHEDULE EVERY 1 HOUR
    DO DELETE FROM sessions WHERE expires_at < NOW();
```

### Storage Implementation

```rust
pub struct MySqlStorage {
    pool: MySqlPool,
}

#[derive(Clone)]
pub struct MySqlHandle {
    pool: MySqlPool,
}

#[derive(Debug, Clone)]
pub struct MySqlConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub ssl_mode: MySqlSslMode,
    pub connection_timeout: Duration,
}

impl MySqlConfig {
    fn to_connection_string(&self) -> String {
        format!(
            "mysql://{}:{}@{}:{}/{}?ssl-mode={}",
            self.username, self.password, self.host, self.port,
            self.database, self.ssl_mode
        )
    }
}

#[async_trait]
impl StoragePlugin for MySqlStorage {
    type Config = MySqlConfig;
    type Handle = MySqlHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        let pool = MySqlPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect_timeout(config.connection_timeout)
            .connect(&config.to_connection_string())
            .await?;

        // Run migrations
        self.migrate(&pool).await?;

        Ok(MySqlHandle { pool })
    }
}
```

### User Storage Implementation

```rust
#[async_trait]
impl UserStorage for MySqlHandle {
    async fn create_user(&self, new_user: &NewUser) -> Result<User, Error> {
        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, password_hash, metadata)
            VALUES (?, ?, ?, ?)
            "#,
            new_user.id.to_string(),
            new_user.email,
            new_user.password_hash,
            serde_json::to_string(&new_user.metadata.unwrap_or_default())?
        )
        .execute(&self.pool)
        .await?;

        // MySQL doesn't support RETURNING, so we need a separate query
        self.get_user_by_id(&new_user.id).await?
            .ok_or_else(|| Error::Storage("Failed to create user".into()))
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id, email, password_hash, email_verified_at,
                metadata, created_at, updated_at
            FROM users
            WHERE email = ?
            "#,
            email
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(Error::from)
    }
}
```

### Session Storage Implementation

```rust
#[async_trait]
impl SessionStorage for MySqlHandle {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        sqlx::query!(
            r#"
            INSERT INTO sessions
                (id, user_id, expires_at, user_agent, ip_address)
            VALUES (?, ?, ?, ?, ?)
            "#,
            session.id.to_string(),
            session.user_id.to_string(),
            session.expires_at,
            session.user_agent,
            session.ip_address,
        )
        .execute(&self.pool)
        .await?;

        Ok(session.clone())
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        sqlx::query!("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
```

### Error Handling

```rust
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::Database(e) => {
                if let Some(code) = e.code() {
                    match code.as_ref() {
                        "23000" => Error::Duplicate, // Duplicate entry
                        "1452" => Error::ForeignKey, // Foreign key constraint
                        _ => Error::Storage(e.to_string()),
                    }
                } else {
                    Error::Storage(e.to_string())
                }
            }
            _ => Error::Storage(err.to_string()),
        }
    }
}
```

## Features

### 1. Full-Text Search

```sql
ALTER TABLE users
ADD FULLTEXT INDEX users_fulltext (email);

-- Usage example
SELECT * FROM users
WHERE MATCH(email) AGAINST ('search term' IN BOOLEAN MODE);
```

### 2. Deadlock Prevention

```rust
impl MySqlHandle {
    async fn with_retry<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: Fn() -> Future<Output = Result<T, Error>>,
    {
        let mut attempts = 0;
        loop {
            match f().await {
                Ok(result) => return Ok(result),
                Err(Error::Deadlock) if attempts < 3 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
```

### 3. Connection Pool Health Checks

```rust
impl MySqlHandle {
    async fn health_check(&self) -> Result<(), Error> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(Error::from)
    }
}
```

## Benefits

1. **Performance**: Optimized for OLTP workloads
2. **Resource Usage**: Efficient memory utilization
3. **Replication**: Built-in primary-replica setup
4. **Compatibility**: Wide platform support
5. **Tooling**: Rich ecosystem of management tools

## Migration Guide

1. **Install Dependencies**:

```toml
[dependencies]
sqlx = { version = "0.8", features = ["mysql", "runtime-tokio-rustls"] }
```

2. **Configure Storage**:

```rust
let config = MySqlConfig {
    host: "localhost".to_string(),
    port: 3306,
    username: "torii".to_string(),
    password: "password".to_string(),
    database: "torii".to_string(),
    max_connections: 5,
    min_connections: 1,
    ssl_mode: MySqlSslMode::Preferred,
    connection_timeout: Duration::from_secs(30),
};

let storage = MySqlStorage::new(config)?;
```

3. **Data Migration**:

```bash
torii migrate --from sqlite --to mysql
```

## MySQL-Specific Considerations

1. **No RETURNING Clause**: Requires separate SELECT after INSERT
2. **Transaction Isolation**: Default REPEATABLE READ
3. **JSON Support**: Less sophisticated than PostgreSQL
4. **Character Sets**: UTF8MB4 recommended
5. **Auto-increment**: Available but using UUIDs for compatibility

## Questions

1. Should we support MySQL-specific features like LOAD DATA INFILE?
2. How should we handle different MySQL versions?
3. Should we support MariaDB compatibility?
4. How do we handle connection pooling in serverless environments?

## Alternatives Considered

1. **ORM Layer**

   - More abstraction
   - Development convenience
   - Performance overhead

2. **Raw SQL**

   - Maximum flexibility
   - Error-prone
   - Version-specific SQL

3. **Query Builder**
   - Balance of safety and control
   - Type-safe queries
   - More verbose

## References

- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)
- [MySQL Documentation](https://dev.mysql.com/doc/)
- [SQLx MySQL Documentation](https://docs.rs/sqlx/latest/sqlx/mysql/)
- [MySQL Security Guide](https://dev.mysql.com/doc/refman/8.0/en/security.html)
