# Torii

[![CI](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/cmackenzie1/torii-rs/branch/main/graph/badge.svg?token=MHF0G453L0)](https://codecov.io/gh/cmackenzie1/torii-rs)
[![docs.rs](https://img.shields.io/docsrs/torii)](https://docs.rs/torii/latest/torii/)
[![Crates.io Version](https://img.shields.io/crates/v/torii)](https://crates.io/crates/torii)

Torii is a powerful authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features through a flexible plugin system.

## Features

- Password-based authentication
- Social OAuth/OpenID Connect
- Passkey/WebAuthn support
- Full data sovereignty - store user data where you want
- Multiple storage backends:
  - SQLite
  - Postgres
  - MySQL

## Quick Start

1. Add dependencies to your `Cargo.toml`:

```toml
[dependencies]
torii = { version = "0.2.0", features = ["sqlite", "password"] }
```

2. Initialize the database:

```rust
let pool = SqliteStorage::connect("sqlite://todos.db?mode=rwc").await
    .expect("Failed to connect to database");
let user_storage = Arc::new(pool.clone());
let session_storage = Arc::new(pool.clone());

// Migrate the user storage
user_storage
    .migrate()
    .await
    .expect("Failed to migrate user storage");

// Migrate the session storage
session_storage
    .migrate()
    .await
    .expect("Failed to migrate session storage");

let torii = Torii::new(user_storage, session_storage).with_password_plugin();
```

3. Create a user:

```rust
let user = torii.register_user_with_password("test@example.com", "password").await?;
```

4. Login a user:

```rust
let user = torii.login_user_with_password("test@example.com", "password").await?;
```
