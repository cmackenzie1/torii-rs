# Torii

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
  - OpenID Connect (OIDC)
  - WebAuthn (Coming Soon)
- 💾 Storage backends
  - SQLite support
  - Postgres support (#3)
  - MySQL support (#4)
- 🔌 Plugin system for extending functionality

## Current Plugins

- [Email/Password Authentication](./torii-auth-email/README.md)
- [OpenID Connect (OIDC)](./torii-auth-oidc/README.md)

## Security

> [!IMPORTANT]
> As this project is in early development, it has not undergone security audits and should not be used in production environments. The maintainers are not responsible for any security issues that may arise from using this software.

## Contributing

As this project is in its early stages, we welcome discussions and feedback, but please note that major changes may occur.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
