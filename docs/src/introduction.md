# Introduction to Torii

Torii is a powerful authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions like Auth0, Clerk, or WorkOS that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features through a flexible service architecture.

With Torii, you get the best of both worlds - powerful authentication capabilities combined with full data sovereignty and the ability to store user data wherever you choose.

> **Warning:** This project is in early development and is not production-ready. The API is subject to change without notice. As this project has not undergone security audits, it should not be used in production environments.

## Key Features

- **Data Sovereignty**: Your user data stays in your own database
- **Multiple Authentication Methods**: 
  - Password-based authentication
  - Social OAuth/OpenID Connect
  - Passkey/WebAuthn support
  - Magic Link authentication
- **Flexible Storage**: Store user data in SQLite, PostgreSQL, or MySQL (using SeaORM)
- **JWT Support**: Optional stateless JWT sessions
- **Extensible Service Architecture**: Add custom authentication methods or storage backends

## Storage Support

| Authentication Method | SQLite | PostgreSQL | MySQL (using SeaORM) |
|-----------------------|--------|------------|----------------------|
| Password              | ✅     | ✅         | ✅                   |
| OAuth2/OIDC           | ✅     | ✅         | ✅                   |
| Passkey               | ✅     | ✅         | ✅                   |
| Magic Link            | ✅     | ✅         | ✅                   |
