# torii-core

Core functionality for the torii project. All plugins are built on top of this library and are responsible for handling the specific details of each authentication method.

Plugins may use the core functionality to handle common tasks such as database migrations, user management, and session management, but are otherwise free to implement the logic in any way they want.

## Users

Users are the core of the authentication system. They are responsible for storing user information and are used to identify users in the system. The core user struct is defined as follows:

| Field               | Type               | Description                                       |
| ------------------- | ------------------ | ------------------------------------------------- |
| `id`                | `String`           | The unique identifier for the user.               |
| `name`              | `String`           | The name of the user.                             |
| `email`             | `String`           | The email of the user.                            |
| `email_verified_at` | `Option<DateTime>` | The timestamp when the user's email was verified. |
| `created_at`        | `DateTime`         | The timestamp when the user was created.          |
| `updated_at`        | `DateTime`         | The timestamp when the user was last updated.     |

## Sessions

Sessions are used to track user sessions and are used to authenticate users. The core session struct is defined as follows:

| Field        | Type             | Description                                            |
| ------------ | ---------------- | ------------------------------------------------------ |
| `id`         | `String`         | The unique identifier for the session.                 |
| `user_id`    | `String`         | The unique identifier for the user.                    |
| `user_agent` | `Option<String>` | The user agent of the client that created the session. |
| `ip_address` | `Option<String>` | The IP address of the client that created the session. |
| `created_at` | `DateTime`       | The timestamp when the session was created.            |
| `updated_at` | `DateTime`       | The timestamp when the session was last updated.       |
| `expires_at` | `DateTime`       | The timestamp when the session will expire.            |
