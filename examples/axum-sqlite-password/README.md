# Torii Axum SQLite Password Example

This example demonstrates how to use the `torii-axum` crate with SQLite in-memory storage via SeaORM and password authentication.

## Features

- **Password Authentication**: User registration and login with passwords
- **SQLite In-Memory Database**: Fast, ephemeral storage perfect for development and testing
- **SeaORM Integration**: Type-safe database operations with automatic migrations
- **Session Management**: Secure cookie-based sessions
- **Bearer Token Authentication**: Support for Authorization header with Bearer tokens
- **Multiple Route Types**: Public, protected, and optional authentication endpoints

## Quick Start

1. **Run the example**:
   ```bash
   cargo run
   ```

2. **Access the application**:
   - Open your browser to `http://localhost:3000`
   - Or use curl/httpie to interact with the API

## API Endpoints

### Authentication Endpoints

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login with email and password
- `POST /auth/password` - Change password (requires authentication)
- `GET /auth/user` - Get current user information (requires authentication)
- `GET /auth/session` - Get current session information (requires authentication)
- `POST /auth/logout` - Logout current user (requires authentication)
- `GET /auth/health` - Health check endpoint

### Example Endpoints

- `GET /` - Index page with API documentation
- `GET /public` - Public endpoint (no authentication required)
- `GET /protected` - Protected endpoint (requires authentication)
- `GET /optional` - Optional authentication endpoint
- `GET /bearer-only` - Bearer token demonstration endpoint
- `GET /token-info` - Token information endpoint (accepts both cookies and Bearer tokens)

## Usage Examples

### Register a new user

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123"}'
```

### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "securepassword123"}' \
  -c cookies.txt
```

### Access protected endpoint with cookies

```bash
curl http://localhost:3000/protected -b cookies.txt
```

### Access protected endpoint with Bearer token

Extract the session token from the login response and use it in the Authorization header:

```bash
# Get session token from login response
SESSION_TOKEN="your_session_token_here"

# Use Bearer token authentication
curl -H "Authorization: Bearer $SESSION_TOKEN" \
  http://localhost:3000/protected
```

### Bearer token specific endpoints

```bash
# Bearer token only endpoint
curl -H "Authorization: Bearer $SESSION_TOKEN" \
  http://localhost:3000/bearer-only

# Token info endpoint (accepts both cookies and Bearer tokens)
curl -H "Authorization: Bearer $SESSION_TOKEN" \
  http://localhost:3000/token-info
```

### Get current user

```bash
curl http://localhost:3000/auth/user -b cookies.txt
```

### Change password

```bash
curl -X POST http://localhost:3000/auth/password \
  -H "Content-Type: application/json" \
  -d '{"current_password": "securepassword123", "new_password": "newsecurepassword456"}' \
  -b cookies.txt
```

### Logout

```bash
curl -X POST http://localhost:3000/auth/logout -b cookies.txt
```

## Code Structure

### Main Components

- **Database Setup**: SQLite in-memory database with automatic migrations
- **Repository Provider**: SeaORM-based storage backend
- **Torii Instance**: Main authentication coordinator
- **Authentication Routes**: Pre-built auth endpoints with cookie configuration
- **Custom Routes**: Example endpoints demonstrating different authentication patterns

### Key Features Demonstrated

1. **In-Memory SQLite**: Perfect for development and testing
2. **Automatic Migrations**: Database schema is set up automatically
3. **Cookie-based Sessions**: Secure session management with configurable settings
4. **Multiple Authentication Patterns**:
   - Required authentication (`AuthUser` extractor)
   - Optional authentication (`OptionalAuthUser` extractor)
   - Bearer token extraction (`SessionTokenFromBearer` extractor)
   - Flexible token extraction (`SessionTokenFromRequest` extractor - tries Bearer first, then cookies)
   - Public endpoints (no authentication)

### Authentication Flow

1. User registers with email and password
2. System creates user account and hashes password
3. User logs in with credentials
4. System creates session and sets secure cookie
5. Subsequent requests include session cookie OR Bearer token in Authorization header
6. Protected endpoints validate session and extract user information
7. Bearer tokens take priority over cookies when both are present

## Development Notes

- Uses SQLite in-memory database (`sqlite::memory:`) for fast startup
- Configured for development with relaxed cookie security
- Includes comprehensive logging for debugging
- All routes return JSON responses
- Session cookies are httpOnly and secure in production

## Configuration

The example uses development cookie configuration:
- `secure`: false (for HTTP development)
- `http_only`: true (prevents XSS attacks)
- `same_site`: Lax (allows cross-site requests)

For production, use `CookieConfig::production()` which enforces HTTPS and stricter security settings.

## Dependencies

- `torii`: Core authentication library
- `torii-axum`: Axum integration with HTTP routes and middleware
- `torii-storage-seaorm`: SeaORM storage backend
- `axum`: Web framework
- `tokio`: Async runtime
- `serde`: JSON serialization
- `tracing`: Logging and observability