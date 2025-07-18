# Axum Example - Complete Torii Integration

This example demonstrates a complete Axum web server with Torii authentication, showcasing:

- **SQLite storage** with SeaORM
- **Password authentication** with built-in routes
- **Email integration** with welcome emails and password change notifications
- **Magic link authentication** with working endpoints
- **Password reset functionality** with secure token-based flow
- **Authentication middleware** for protecting routes
- **Multiple authentication extractors** (AuthUser, OptionalAuthUser, etc.)

## Features Demonstrated

### Built-in Authentication Routes (via `torii-axum`)
- `POST /auth/register` - User registration (with automatic welcome email)
- `POST /auth/login` - User login  
- `POST /auth/password` - Change password (with automatic email notification)
- `POST /auth/password/reset/request` - Request password reset via email
- `POST /auth/password/reset/verify` - Verify password reset token
- `POST /auth/password/reset/confirm` - Confirm password reset with new password
- `GET /auth/user` - Get current user
- `GET /auth/session` - Get current session
- `POST /auth/logout` - User logout
- `GET /auth/health` - Health check

### Additional Example Routes
- `POST /magic-link` - Request magic link (sends email with authentication link)
- `GET /magic-link/:token` - Verify magic link (authenticates user via token)

### Demo Routes
- `GET /` - API documentation and examples
- `GET /public` - Public endpoint (no auth required)
- `GET /protected` - Protected endpoint (requires authentication)
- `GET /optional` - Optional authentication endpoint
- `GET /bearer-only` - Bearer token only endpoint
- `GET /token-info` - Token information endpoint

## Running the Example

```bash
cd examples/axum-example
cargo run
```

The server will start on `http://localhost:3000` with a complete web interface for testing all authentication methods. Emails will be saved to the `./emails/` directory for local development.

## Email Configuration

By default, the example uses file-based email transport for local development. Emails are saved as `.eml` files in the `./emails/` directory.

For production SMTP, set these environment variables:
```bash
export MAILER_SMTP_HOST=smtp.gmail.com
export MAILER_SMTP_PORT=587
export MAILER_SMTP_USERNAME=your-email@gmail.com
export MAILER_SMTP_PASSWORD=your-app-password
export MAILER_FROM_ADDRESS=noreply@yourapp.com
export MAILER_APP_NAME="Your App"
export MAILER_APP_URL=https://yourapp.com
```

## Example API Usage

### Register User (automatically sends welcome email)
```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Login and Get Session Token
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com", 
    "password": "securepassword123"
  }'
```

### Access Protected Endpoint
```bash
curl http://localhost:3000/protected \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN"
```

### Change Password (automatically sends notification email)
```bash
curl -X POST http://localhost:3000/auth/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_SESSION_TOKEN" \
  -d '{
    "current_password": "securepassword123",
    "new_password": "newsecurepassword456"
  }'
```

### Request Magic Link
```bash
curl -X POST http://localhost:3000/magic-link \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### Verify Magic Link (use token from email)
```bash
curl http://localhost:3000/magic-link/YOUR_MAGIC_TOKEN
```

### Request Password Reset
```bash
curl -X POST http://localhost:3000/auth/password/reset/request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com"
  }'
```

### Verify Reset Token
```bash
curl -X POST http://localhost:3000/auth/password/reset/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_RESET_TOKEN"
  }'
```

### Confirm Password Reset
```bash
curl -X POST http://localhost:3000/auth/password/reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_RESET_TOKEN",
    "new_password": "newsecurepassword456"
  }'
```

## What This Example Shows

1. **Complete Setup**: How to configure Torii with SQLite, password auth, and automatic email support
2. **Built-in Email Integration**: Standard authentication routes automatically send emails when mailer is configured
3. **Authentication Middleware**: Protecting routes with session validation  
4. **Multiple Auth Patterns**: Different authentication extractors (required, optional, bearer-only)
5. **Magic Link Authentication**: Working passwordless authentication via email links
6. **Password Reset Flow**: Secure token-based password reset with email notifications
7. **Error Handling**: Proper error responses and logging
8. **Local Development**: File-based email transport for easy testing
9. **Interactive Web UI**: Full-featured HTML interface for testing all authentication methods

This represents the most comprehensive Torii setup for web applications - featuring every authentication method with automatic email notifications and a complete user interface for testing.