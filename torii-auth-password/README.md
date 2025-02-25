# torii-auth-password

This plugin provides email and password authentication for Torii.

It uses the `password_auth` crate to hash (default hashing algorithm is argon2) and verify passwords and stores the
hashed password in the database.

## Registration Flow

1. User enters their email and password.
2. The plugin hashes the password and stores the hashed password in the database.
3. The plugin returns a `User` object with the user's id and username (email).

## Authentication Flow

1. User enters their email and password.
2. The plugin hashes the password and verifies it against the stored hash.
3. If the password is correct, the user is authenticated and the plugin returns a `User` object with the user's id and username (email).
4. If the password is incorrect, the user is not authenticated and the plugin returns an error.

## TODO

- [ ] Add trait for password validation
- [ ] Add pre-create and pre-update hooks
