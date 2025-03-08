# Core Concepts

Torii is built around several core concepts that form the foundation of the authentication system. Understanding these concepts is essential for effectively implementing and extending Torii in your applications.

## Users

Users are the central entity in the Torii authentication system. Each user represents an individual who can authenticate with your application.

### User Structure

The core User struct contains the following fields:

| Field             | Type                    | Description                                    |
| ----------------- | ----------------------- | ---------------------------------------------- |
| id                | `UserId`                | The unique identifier for the user             |
| name              | `Option<String>`        | The user's name (optional)                     |
| email             | `String`                | The user's email address                       |
| email_verified_at | `Option<DateTime<Utc>>` | Timestamp when the email was verified (if any) |
| created_at        | `DateTime<Utc>`         | Timestamp when the user was created            |
| updated_at        | `DateTime<Utc>`         | Timestamp when the user was last updated       |

### User IDs

Each user has a unique UserId that identifies them in the system. This ID is:

- Stable and will not change during the user's lifetime
- Treated as an opaque string rather than a specific format (though it uses UUIDs internally by default)
- Used to link user accounts to authentication methods, sessions, and application data

### OAuth Accounts

For OAuth-based authentication, Torii maintains OAuthAccount records that link a user to their external provider identities:

| Field      | Type            | Description                              |
| ---------- | --------------- | ---------------------------------------- |
| user_id    | `UserId`        | The Torii user ID                        |
| provider   | `String`        | The OAuth provider (e.g., "google")      |
| subject    | `String`        | The unique ID from the provider          |
| created_at | `DateTime<Utc>` | Timestamp when the link was created      |
| updated_at | `DateTime<Utc>` | Timestamp when the link was last updated |

This allows a single user to authenticate with multiple OAuth providers while maintaining a unified identity within your application.

### Sessions

Sessions represent authenticated user sessions and are created when a user successfully logs in.

#### Session Structure

The Session struct contains the following fields:

| Field      | Type             | Description                                           |
| ---------- | ---------------- | ----------------------------------------------------- |
| token      | `SessionToken`   | The unique token identifying the session              |
| user_id    | `UserId`         | The ID of the authenticated user                      |
| user_agent | `Option<String>` | The user agent of the client that created the session |
| ip_address | `Option<String>` | The IP address of the client that created the session |
| created_at | `DateTime<Utc>`  | Timestamp when the session was created                |
| updated_at | `DateTime<Utc>`  | Timestamp when the session was last updated           |
| expires_at | `DateTime<Utc>`  | Timestamp when the session will expire                |

#### Session Tokens

Each session is identified by a unique SessionToken that:

- Functions as a bearer token or cookie for authentication
- Should be kept secret and transmitted securely (e.g. HTTPS)
- Has an expiration time after which it will no longer be valid
- Can be revoked to force a user to log out

### Session Management

Torii provides several methods for managing sessions:

- Creating sessions: Generate new sessions when users log in
- Verifying sessions: Validate session tokens on subsequent requests
- Expiring sessions: Sessions automatically expire after their configured lifetime
- Revoking sessions: Explicitly invalidate sessions to force logout
  - Cleaning up: Remove expired sessions to maintain database hygiene

### Relationship Between Users and Sessions

In Torii:

- One-to-many relationship: A user can have multiple active sessions (login from different devices)
- Session verification: When a session token is verified, Torii returns both the session and associated user
- Session cleanup: When a user is deleted, all associated sessions are automatically removed
- User lookup: Sessions store the user ID for efficient user lookup during authentication
  Understanding these core concepts provides the foundation for working with Torii's authentication flows, which we'll explore in the subsequent sections.
