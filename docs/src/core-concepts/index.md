# Core Concepts

Torii is an authentication framework that gives you control over your users' data while providing modern authentication features. Here are the essential concepts you need to understand.

## Key Components

Torii consists of four main parts:

- **Torii Instance**: The main coordinator that handles all authentication
- **Storage**: Where user and session data is stored (SQLite, PostgreSQL, MySQL)
- **Authentication Methods**: Password, OAuth, Passkeys, Magic Links
- **Sessions**: How users stay authenticated after login

## Users

Users are people who can authenticate with your application. Each user has:

- **Unique ID**: A stable identifier that never changes
- **Email**: Their email address (required)
- **Name**: Optional display name
- **Verification Status**: Whether their email is verified
- **Timestamps**: When they were created and last updated

## Sessions

Sessions keep users authenticated after they log in. Each session has:

- **Token**: A secret string that identifies the session
- **User ID**: Which user the session belongs to
- **Expiration**: When the session expires
- **Client Info**: Optional user agent and IP address

### Session Types

Torii supports two session types:

1. **Database Sessions** (default): Stored in your database, can be revoked immediately
2. **JWT Sessions**: Self-contained tokens, fast but cannot be revoked

## Authentication Methods

Torii supports multiple ways for users to authenticate:

- **Password**: Traditional email/password login
- **OAuth**: Social login (Google, GitHub, etc.)
- **Passkeys**: Modern biometric authentication
- **Magic Links**: Email-based passwordless login

## Storage

Torii can store data in multiple databases:

- **SQLite**: Great for development and small applications
- **PostgreSQL**: Production-ready relational database
- **MySQL**: Via SeaORM integration

All storage backends support all authentication methods.

## Basic Usage

Here's the typical flow:

1. Set up storage and create a Torii instance
2. Register users with your chosen authentication method
3. Users log in to create sessions
4. Validate sessions to authenticate requests
5. Users log out to end sessions

This simple foundation supports all of Torii's authentication features.
