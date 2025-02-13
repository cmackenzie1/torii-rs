# RFC 0004: PostgreSQL Storage Provider

**Status**: Draft - Not thoroughly reviewed

## Summary

Add PostgreSQL as a storage provider for Torii, implementing the storage interface defined in RFC 0002 while leveraging PostgreSQL-specific features for improved performance and data integrity.

## Motivation

PostgreSQL offers several compelling advantages as a storage backend:

1. **ACID Compliance**: Full transaction support with strong consistency guarantees
2. **Advanced Features**: Rich set of data types, JSON support, and full-text search
3. **Mature Ecosystem**: Extensive tooling and hosting options
4. **Schema Enforcement**: Strong typing and constraints for data integrity
5. **Performance**: Excellent query optimization and indexing capabilities

## Design

### Database Schema

```sql
-- Core schema for users and sessions
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    email_verified_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);

-- Automatic updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();
```

### Storage Implementation

```rust
pub struct PostgresStorage {
    pool: PgPool,
}

#[derive(Clone)]
pub struct PostgresHandle {
    pool: PgPool,
}

#[derive(Debug, Clone)]
pub struct PostgresConfig {
    pub connection_string: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connect_timeout: Duration,
    pub ssl_mode: PgSslMode,
}

#[async_trait]
impl StoragePlugin for PostgresStorage {
    type Config = PostgresConfig;
    type Handle = PostgresHandle;

    async fn initialize(&self, config: Self::Config) -> Result<Self::Handle, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect_timeout(config.connect_timeout)
            .connect(&config.connection_string)
            .await?;

        // Run migrations
        self.migrate(&pool).await?;

        Ok(PostgresHandle { pool })
    }
}
```

### User Storage Implementation

```rust
#[async_trait]
impl UserStorage for PostgresHandle {
    async fn create_user(&self, new_user: &NewUser) -> Result<User, Error> {
        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, email, password_hash, metadata)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, password_hash, email_verified_at,
                      metadata, created_at, updated_at
            "#,
            new_user.id,
            new_user.email,
            new_user.password_hash,
            new_user.metadata.as_ref().unwrap_or(&serde_json::Value::Null),
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Error::from)
    }

    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, Error> {
        sqlx::query_as!(
            User,
            "SELECT * FROM users WHERE email = $1",
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
impl SessionStorage for PostgresHandle {
    async fn create_session(&self, session: &Session) -> Result<Session, Error> {
        sqlx::query_as!(
            Session,
            r#"
            INSERT INTO sessions (id, user_id, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            "#,
            session.id,
            session.user_id,
            session.expires_at,
            session.user_agent,
            session.ip_address,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(Error::from)
    }

    async fn cleanup_expired_sessions(&self) -> Result<(), Error> {
        sqlx::query!(
            "DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP"
        )
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
                        "23505" => Error::Duplicate, // unique_violation
                        "23503" => Error::ForeignKey, // foreign_key_violation
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
ALTER TABLE users ADD COLUMN search_vector tsvector
    GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(email,'')), 'A') ||
        setweight(to_tsvector('english', coalesce(metadata::text,'')), 'B')
    ) STORED;

CREATE INDEX users_search_idx ON users USING GIN (search_vector);
```

### 2. Row-Level Security

```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation ON users
    FOR ALL
    USING (id = current_user_id());

CREATE POLICY session_isolation ON sessions
    FOR ALL
    USING (user_id = current_user_id());
```

### 3. Audit Logging

```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    table_name TEXT NOT NULL,
    record_id UUID NOT NULL,
    operation TEXT NOT NULL,
    old_data JSONB,
    new_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Benefits

1. **Data Integrity**: Strong schema validation and constraints
2. **Performance**: Sophisticated query planner and indexing
3. **Security**: Row-level security and audit logging
4. **Extensibility**: Rich set of data types and extensions
5. **Tooling**: Mature ecosystem of management tools

## Migration Guide

1. **Install Dependencies**:

```toml
[dependencies]
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio-rustls"] }
```

2. **Configure Storage**:

```rust
let config = PostgresConfig {
    connection_string: "postgres://user:pass@localhost/torii",
    max_connections: 5,
    min_connections: 1,
    connect_timeout: Duration::from_secs(30),
    ssl_mode: PgSslMode::Prefer,
};

let storage = PostgresStorage::new(config)?;
```

3. **Data Migration**:

```bash
# Export from SQLite
sqlite3 torii.db .dump > dump.sql

# Import to PostgreSQL
torii migrate --from sqlite --to postgres
```

## Questions

1. Should we support PostgreSQL-specific features like LISTEN/NOTIFY?
2. How should we handle schema migrations?
3. Should we support PostgreSQL extensions (e.g., PostGIS)?
4. How do we handle connection pooling in serverless environments?

## Alternatives Considered

1. **ORM Layer**

   - More abstraction
   - Better development experience
   - Performance overhead

2. **Raw SQL**

   - Maximum flexibility
   - More error-prone
   - Less maintainable

3. **Query Builder**
   - Balance of safety and control
   - Type-safe queries
   - More verbose than ORM

## References

- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)
- [SQLx Documentation](https://docs.rs/sqlx)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [PostgreSQL Security Guide](https://www.postgresql.org/docs/current/security.html)
