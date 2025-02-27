# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
