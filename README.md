# Torii

[![CI](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/cmackenzie1/torii-rs/branch/main/graph/badge.svg?token=MHF0G453L0)](https://codecov.io/gh/cmackenzie1/torii-rs)
[![docs.rs](https://img.shields.io/docsrs/torii)](https://docs.rs/torii/latest/torii/)
[![Crates.io Version](https://img.shields.io/crates/v/torii)](https://crates.io/crates/torii)

![Torii Logo](./assets/splash.jpeg)

> [!WARNING]
> This project is in early development and is not production-ready. The API is subject to change without notice.

## Overview

Torii is a flexible authentication framework for Rust applications that provides a plugin-based system for multiple authentication methods. It's designed to be simple to use while remaining extensible for various authentication needs.

## Development Status

- 🚧 Early Development
- ⚠️ Not Production Ready
- 📝 APIs Subject to Change

## Features

- 🔐 Multiple authentication methods
  - Email/Password authentication
  - OAuth2 / OpenID Connect (OIDC)
  - Passkey authentication
- 💾 Storage backends
  - SQLite support
  - Postgres support
  - MySQL support (https://github.com/cmackenzie1/torii-rs/issues/4)
- 🔌 Plugin system for extending functionality

## Current Plugins

- [Email/Password Authentication](./torii-auth-password/README.md)
- [OAuth2 / OpenID Connect (oidc)](./torii-auth-oauth/README.md)
- [Passkey Authentication](./torii-auth-passkey/README.md)

## Security

> [!IMPORTANT]
> As this project is in early development, it has not undergone security audits and should not be used in production environments. The maintainers are not responsible for any security issues that may arise from using this software.

## Contributing

As this project is in its early stages, we welcome discussions and feedback, but please note that major changes may occur.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
