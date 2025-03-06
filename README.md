# Torii

[![CI](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/cmackenzie1/torii-rs/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/cmackenzie1/torii-rs/branch/main/graph/badge.svg?token=MHF0G453L0)](https://codecov.io/gh/cmackenzie1/torii-rs)
[![docs.rs](https://img.shields.io/docsrs/torii)](https://docs.rs/torii/latest/torii/)
[![Crates.io Version](https://img.shields.io/crates/v/torii)](https://crates.io/crates/torii)

> [!WARNING]
> This project is in early development and is not production-ready. The API is subject to change without notice.

## Overview

Torii is a powerful authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features through a flexible plugin system.

With Torii, you get the best of both worlds - powerful authentication capabilities like passwordless login, social OAuth, and passkeys, combined with full data sovereignty and the ability to store user data wherever you choose.

Checkout the example [todos](./examples/todos/README.md) to see Torii in action.

## Features

| Plugin                                          | SQLite | PostgreSQL | MySQL                                                     |
| ----------------------------------------------- | ------ | ---------- | --------------------------------------------------------- |
| [Password](./torii-auth-password/README.md)     | ✅     | ✅         | 🚧 [#4](https://github.com/cmackenzie1/torii-rs/issues/4) |
| [OAuth2/OIDC](./torii-auth-oauth/README.md)     | ✅     | ✅         | 🚧 [#4](https://github.com/cmackenzie1/torii-rs/issues/4) |
| [Passkey](./torii-auth-passkey/README.md)       | ✅     | ✅         | 🚧 [#4](https://github.com/cmackenzie1/torii-rs/issues/4) |
| [Magic Link](./torii-auth-magic-link/README.md) | ✅     | ✅         | 🚧 [#4](https://github.com/cmackenzie1/torii-rs/issues/4) |

✅ = Supported
🚧 = Planned/In Development
❌ = Not Supported

## Security

> [!IMPORTANT]
> As this project is in early development, it has not undergone security audits and should not be used in production environments. The maintainers are not responsible for any security issues that may arise from using this software.

## Contributing

As this project is in its early stages, we welcome discussions and feedback, but please note that major changes may occur.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
