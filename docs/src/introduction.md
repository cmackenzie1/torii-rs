# Introduction to Torii

Torii is an authentication framework for Rust applications that gives you complete control over your users' data. Unlike hosted solutions that store user information in their cloud, Torii lets you own and manage your authentication stack while providing modern auth features.

With Torii, you get powerful authentication capabilities combined with full data sovereignty and the ability to store user data wherever you choose.

> **Warning:** This project is in early development and is not production-ready. The API is subject to change without notice. As this project has not undergone security audits, it should not be used in production environments.

## Key Features

- **Data Sovereignty**: Your user data stays in your own database
- **Multiple Authentication Methods**: 
  - Password-based authentication
  - Social OAuth/OpenID Connect
  - Passkey/WebAuthn support
  - Magic Link authentication
- **Flexible Storage**: Store user data in SQLite, PostgreSQL, or MySQL
- **Session Management**: Choose between database sessions or JWT tokens
- **Type Safety**: Strongly typed APIs with compile-time guarantees

## Storage Support

| Authentication Method | SQLite | PostgreSQL | MySQL |
|-----------------------|--------|------------|-------|
| Password              | ✅     | ✅         | ✅    |
| OAuth2/OIDC           | ✅     | ✅         | ✅    |
| Passkey               | ✅     | ✅         | ✅    |
| Magic Link            | ✅     | ✅         | ✅    |
