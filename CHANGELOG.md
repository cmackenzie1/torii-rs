# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### `torii-auth-magic-link`

A new plugin for generating and verifying magic links has been added.

### Changed

#### `torii-core`

- `SessionStorage::get_session` now returns a `Result<Session, Error>` instead of `Result<Option<Session>, Error>`. Users should check the error for details on if the session was found, or expired.
- Session creation, deletion, and cleanup are now handled by the `SessionManager` trait and the `DefaultSessionManager` implementation.
- Plugins no longer require a `SessionStorage` parameter, the top level `Torii` struct now holds a `SessionManager` instance and login methods continue to return a `Session` instance.

### Removed

#### `torii-core`

- `Storage<U,S>` struct has been removed. Use `Arc<U>` and `Arc<S>` directly instead.
- `AsRef<UserId> and AsRef<SessionId>` have been removed. Use `as_str()` instead when needing a database serializable string.

## [0.2.0] - 2025-02-27

### Added

This is the first release of the torii authentication ecosystem, it includes the following crates:

- `torii-core`: Core functionality for the torii authentication ecosystem.
- `torii-auth-password`: Password authentication plugin for the torii authentication ecosystem.
- `torii-auth-oauth`: OAuth authentication plugin for the torii authentication ecosystem.
- `torii-auth-passkey`: Passkey authentication plugin for the torii authentication ecosystem.
- `torii-storage-sqlite`: SQLite storage backend for the torii authentication ecosystem.
- `torii-storage-postgres`: Postgres storage backend for the torii authentication ecosystem.
- `torii`: Main crate for the torii authentication ecosystem.

Users should use the `torii` crate with feature flags to enable the authentication plugins and storage backends they need.

```toml
[dependencies]
torii = { version = "0.2.0", features = ["password", "sqlite"] }
```
