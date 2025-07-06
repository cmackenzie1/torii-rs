# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2025-07-06

### Added

- Re-enabled SeaORM storage backend integration
- Split session providers into separate opaque and JWT implementations for better modularity
- Added API endpoints for changing passwords and deleting users
- Added user info endpoint for OAuth code exchange flow
- Updated dependencies to Rust 1.87

### Changed

- **BREAKING CHANGE**: Complete architectural transformation from plugins to services
  - Migrated from a plugin-based architecture to a service-oriented design
  - All authentication methods now implement service traits instead of plugin interfaces
  - Improved separation of concerns between authentication logic and storage
- Email validation is now optional for login operations
- Re-exported `JwtConfig` in the main crate for easier access

### Fixed

- JWT session tests now pass correctly
- Re-export of `JwtConfig` in main crate (issue #51)
