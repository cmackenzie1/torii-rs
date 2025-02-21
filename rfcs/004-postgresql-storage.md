# RFC 004: PostgreSQL Storage Provider

| Date       | Author       | Status         |
| ---------- | ------------ | -------------- |
| 2025-02-19 | @cmackenzie1 | ✅ Implemented |

## Summary

Add PostgreSQL as a storage provider for Torii, implementing the core storage interfaces while leveraging PostgreSQL's features for improved reliability and performance.

## Motivation

PostgreSQL offers several compelling advantages as a storage backend:

1. **ACID Compliance**: Full transaction support with strong consistency guarantees
2. **Reliability**: Mature, battle-tested database with excellent durability
3. **Performance**: Connection pooling and efficient query execution
4. **Schema Enforcement**: Strong typing and constraints for data integrity
5. **Ecosystem**: Wide hosting options and management tools

## Design

### Core Tables

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    email TEXT UNIQUE,
    email_verified_at TIMESTAMPTZ,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID,
    user_agent TEXT,
    ip_address TEXT,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, provider, subject)
);

CREATE TABLE nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
```

### Storage Implementation

The PostgreSQL storage provider implements the following core interfaces:

- `UserStorage` - For managing user accounts
- `SessionStorage` - For handling user sessions
- `EmailPasswordStorage` - For email/password authentication
- `OAuthStorage` - For OAuth account linking

Key implementation details:

```rust
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        let migrations = sqlx::migrate!("./migrations");
        migrations.run(&self.pool).await?;
        Ok(())
    }
}
```

### Features

1. **Connection Pooling**: Efficient connection management via sqlx
2. **Migration Support**: Built-in schema migrations
3. **Strong Typing**: Type-safe database interactions
4. **Automatic Timestamps**: Created/updated timestamps handled by database
5. **Referential Integrity**: Foreign key constraints for data consistency

## Usage

1. Add dependencies:

```toml
[dependencies]
torii-storage-postgres = { version = "0.1" }
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }
```

2. Initialize storage:

```rust
let pool = PgPool::connect("postgres://user:pass@localhost/db").await?;
let storage = PostgresStorage::new(pool);
storage.migrate().await?;
```

## Benefits

1. **Production Ready**: Stable, tested implementation
2. **Type Safety**: Compile-time query checking
3. **Performance**: Efficient connection pooling
4. **Maintainability**: Clear schema migrations
5. **Security**: Built-in password hashing support

## Migration Guide

For users migrating from another storage provider:

1. Set up PostgreSQL database
2. Update configuration to use PostgreSQL connection string
3. Run migrations via `storage.migrate()`
4. Data migration tools provided separately

## References

- [SQLx Documentation](https://docs.rs/sqlx)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [RFC 0002: Plugin Interfaces](./002-plugin-interfaces.md)

## Known Limitations

1. No built-in read replicas support
2. Connection pool sizing needs manual tuning
3. No automatic backup management
