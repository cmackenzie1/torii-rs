# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `JwtConfig` is now re-exported for use in `torii` crate.

## [0.3.0] - 2025-06-26

### Added

- Added a new crate, `torii-storage-seaorm`, which is a storage backend for the torii authentication ecosystem that uses SeaORM to target SQLite, Postgres, and MySQL.
- Added JWT-based session support with configurable expiry time.
  - `JwtSessionManager`: A session manager that uses JWTs to store session data without requiring database lookup.
  - JWT sessions can store user metadata (IP, user agent) directly in the token.
  - JWT sessions can be configured with a custom issuer and expiration time.
  - Support for both RS256 (RSA+SHA256) and HS256 (HMAC+SHA256) algorithms:
    - RS256: Uses asymmetric cryptography with separate signing and verification keys
    - HS256: Uses symmetric cryptography with a single secret key
- Updated passkey example to use SimpleWebAuthn browser library from the CDN for improved WebAuthn support

### Changed

#### `torii-core`

- `SessionStorage::get_session` now returns a `Result<Option<Session>, Error>` instead of `Result<Session, Error>`. This reverts the change from `0.2.3`.
- `SessionToken` type now supports both opaque tokens and JWT tokens.
- Added `JwtConfig` for configuring JWT session parameters.
- Added `UserManager` trait to standardize user management operations.
- Added `DefaultUserManager` implementation that wraps a `UserStorage`.

#### Authentication Plugins

- **BREAKING CHANGE**: Refactored all auth plugins to support the new UserManager architecture:
  - `PasswordPlugin` now accepts a UserManager and PasswordStorage
  - `OAuthPlugin` now accepts a UserManager and OAuthStorage
  - `PasskeyPlugin` now accepts a UserManager and PasskeyStorage
  - `MagicLinkPlugin` now accepts a UserManager and MagicLinkStorage
  - All plugins now delegate user operations to the UserManager and use storage for auth-specific operations
  - Updated examples to demonstrate proper usage with the new architecture

#### `torii-auth-passkey`

- **BREAKING CHANGE**: Completely redesigned the passkey authentication API for improved type safety and usability:
  - Added a `PasskeyAuthPlugin` trait to define standardized authentication methods
  - Replaced string and JSON value parameters with proper strongly-typed structures:
    - `PasskeyRegistrationRequest` and `PasskeyRegistrationCompletion`
    - `PasskeyLoginRequest` and `PasskeyLoginCompletion`
    - `ChallengeId` type for better type safety
  - Created separate public-facing credential types:
    - `PasskeyCredentialCreationOptions`
    - `PasskeyCredentialRequestOptions`
  - Enhanced error handling with detailed context information using `PasskeyErrorContext`
  - Updated the `torii` integration to use the new API with both structured types and convenient alternatives

#### `torii`

- **BREAKING CHANGE**: Redesigned Torii struct to simplify type parameters and support separate storage backends:
  - Reduced generic parameters from 3 to 2, keeping only storage types and using trait objects for managers
  - Added more flexible constructors:
    - `new(storage)`: Simplest case with single storage for both users and sessions
    - `with_storages(user_storage, session_storage)`: For separate storage backends
    - `with_managers(user_storage, session_storage, user_manager, session_manager)`: For custom managers with plugin support
    - `with_custom_managers(user_manager, session_manager)`: For standalone managers without plugin support
  - Added explanatory documentation for each approach
  - Updated example application to demonstrate the different usage patterns

- Login methods now accept an optional user agent and ip address parameter which will be stored with the session in the database.
- Added new methods to configure session type:
  - `with_jwt_sessions()`: Configure Torii to use JWT sessions exclusively
- Session configuration now supports JWT settings through `SessionConfig`.
- **Magic Link API**: Fixed `generate_magic_token()` to return the generated token rather than discarding it
  - The method now returns `Result<MagicToken, ToriiError>` instead of `Result<(), ToriiError>`
  - Consistently use `"magic_link"` for plugin name (was inconsistently using `"magic-link"`)
  - Added re-export of the `MagicToken` type from `torii_core`
  - Improved documentation for both token generation and verification

## [0.2.3] - 2025-03-05

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

---

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
