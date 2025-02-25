# torii-storage-postgres

This crate provides a Postgres storage implementation for Torii.

It provides implementations for the following traits:

- `UserStorage` - for storing and retrieving users
- `SessionStorage` - for storing and retrieving sessions
- `EmailAuthStorage` - for use by the `torii-auth-password` plugin
