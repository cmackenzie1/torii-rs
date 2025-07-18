use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use torii::seaorm::SeaORMStorage;
use torii::{MailerConfig, Torii};
use torii_axum::{
    AuthUser, CookieConfig, OptionalAuthUser, SessionTokenFromBearer, SessionTokenFromRequest,
};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("info,axum_sqlite_password_example=debug,torii=debug")
        .init();

    info!("Starting Torii Axum SQLite Password Example");

    // Connect to SQLite in-memory database
    let storage = SeaORMStorage::connect("sqlite::memory:").await?;

    // Run migrations to set up the database schema
    storage.migrate().await?;
    info!("Database migrations completed");

    // Configure mailer for local development (saves emails to files)
    let mailer_config = MailerConfig::default();

    // Create repository provider and Torii instance with mailer
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Arc::new(Torii::new(repositories).with_mailer(mailer_config)?);

    // Configure session cookies for development
    let cookie_config = CookieConfig::development();

    // Create authentication routes
    let auth_routes = torii_axum::routes(torii.clone())
        .with_cookie_config(cookie_config.clone())
        .build();

    // Create auth state for middleware
    let auth_state = torii_axum::AuthState {
        torii: torii.clone(),
    };

    // Create additional routes that use Torii state
    let additional_routes = Router::new()
        .route("/magic-link", post(request_magic_link_handler))
        .route("/magic-link/{token}", get(verify_magic_link_handler))
        .with_state(torii.clone());

    // Create the main application
    let app = Router::new()
        .nest("/auth", auth_routes)
        .route("/", get(index_handler))
        .route("/public", get(public_handler))
        .route("/protected", get(protected_handler))
        .route("/optional", get(optional_auth_handler))
        .route("/bearer-only", get(bearer_only_handler))
        .route("/token-info", get(token_info_handler))
        .merge(additional_routes)
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            torii_axum::auth_middleware,
        ))
        .layer(axum::Extension(cookie_config));

    info!("Server starting on http://localhost:3000");
    info!("📧 Emails will be saved to ./emails/ directory");
    info!("Available endpoints:");
    info!("  GET  /                    - Index page");
    info!("  GET  /public              - Public endpoint");
    info!("  GET  /protected           - Protected endpoint (requires authentication)");
    info!("  GET  /optional            - Optional authentication endpoint");
    info!("  GET  /bearer-only         - Bearer token only endpoint");
    info!("  GET  /token-info          - Token information endpoint");
    info!(
        "  POST /auth/register                - Register new user (with automatic welcome email)"
    );
    info!("  POST /auth/login                   - Login user");
    info!("  POST /auth/password                - Change password (with automatic email notification)");
    info!("  POST /auth/password/reset/request  - Request password reset");
    info!("  POST /auth/password/reset/verify   - Verify password reset token");
    info!("  POST /auth/password/reset/confirm  - Confirm password reset");
    info!("  GET  /auth/user                    - Get current user");
    info!("  GET  /auth/session                 - Get current session");
    info!("  POST /auth/logout                  - Logout user");
    info!("  GET  /auth/health                  - Health check");
    info!("  POST /magic-link                   - Request magic link (placeholder)");
    info!("  GET  /magic-link/{{token}}           - Verify magic link (placeholder)");

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_handler(
    user: OptionalAuthUser,
    token: SessionTokenFromRequest,
    bearer_token: SessionTokenFromBearer,
) -> Html<String> {
    // Determine authentication source
    let auth_source = if bearer_token.0.is_some() {
        "Authorization Header (Bearer)"
    } else if token.0.is_some() {
        "Session Cookie"
    } else {
        "None"
    };

    // Prepare user data for JavaScript
    let user_data = match user.0 {
        Some(ref user) => format!(
            r#"{{
                "authenticated": true,
                "user": {{
                    "id": "{}",
                    "email": "{}",
                    "name": {},
                    "email_verified": {},
                    "created_at": "{}"
                }},
                "auth_source": "{}"
            }}"#,
            user.id,
            user.email,
            user.name
                .as_ref()
                .map_or("null".to_string(), |name| format!("\"{name}\"")),
            user.is_email_verified(),
            user.created_at.to_rfc3339(),
            auth_source
        ),
        None => r#"{"authenticated": false, "user": null, "auth_source": "None"}"#.to_string(),
    };

    let html_template = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Torii Authentication Example</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .section h2 {
            margin-top: 0;
            color: #555;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="email"], input[type="password"], input[type="text"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        button {
            background-color: #007bff;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .btn-secondary {
            background-color: #6c757d;
        }
        .btn-secondary:hover {
            background-color: #545b62;
        }
        .status {
            margin-top: 15px;
            padding: 10px;
            border-radius: 4px;
            display: none;
        }
        .status.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .status.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .user-info {
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 15px;
        }
        .endpoint-test {
            margin-top: 15px;
        }
        .endpoint-test button {
            margin-right: 10px;
            margin-bottom: 5px;
        }
        .response {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 10px;
            white-space: pre-wrap;
            font-family: monospace;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Torii Authentication Example</h1>

        <div id="user-status" class="user-info" style="display: none;">
            <h3>Current User</h3>
            <div id="user-details"></div>
            <button onclick="logout()">Logout</button>
        </div>

        <div class="section">
            <h2>🔑 Authentication</h2>

            <div style="display: flex; gap: 20px;">
                <div style="flex: 1;">
                    <h3>Register</h3>
                    <div class="form-group">
                        <label for="register-email">Email:</label>
                        <input type="email" id="register-email" placeholder="user@example.com">
                    </div>
                    <div class="form-group">
                        <label for="register-password">Password:</label>
                        <input type="password" id="register-password" placeholder="Enter password">
                    </div>
                    <button onclick="register()">Register</button>
                    <div id="register-status" class="status"></div>
                </div>

                <div style="flex: 1;">
                    <h3>Login</h3>
                    <div class="form-group">
                        <label for="login-email">Email:</label>
                        <input type="email" id="login-email" placeholder="user@example.com">
                    </div>
                    <div class="form-group">
                        <label for="login-password">Password:</label>
                        <input type="password" id="login-password" placeholder="Enter password">
                    </div>
                    <button onclick="login()">Login</button>
                    <div id="login-status" class="status"></div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🔗 Magic Link</h2>
            <div class="form-group">
                <label for="magic-email">Email:</label>
                <input type="email" id="magic-email" placeholder="user@example.com">
            </div>
            <button onclick="requestMagicLink()">Request Magic Link</button>
            <div id="magic-status" class="status"></div>
        </div>

        <div class="section">
            <h2>🔄 Password Reset</h2>

            <div style="display: flex; gap: 20px;">
                <div style="flex: 1;">
                    <h3>Request Password Reset</h3>
                    <div class="form-group">
                        <label for="reset-email">Email:</label>
                        <input type="email" id="reset-email" placeholder="user@example.com">
                    </div>
                    <button onclick="requestPasswordReset()">Request Password Reset</button>
                    <div id="reset-request-status" class="status"></div>
                </div>

                <div style="flex: 1;">
                    <h3>Reset Password</h3>
                    <div class="form-group">
                        <label for="reset-token">Reset Token:</label>
                        <input type="text" id="reset-token" placeholder="Enter reset token">
                    </div>
                    <div class="form-group">
                        <label for="new-password">New Password:</label>
                        <input type="password" id="new-password" placeholder="Enter new password">
                    </div>
                    <div style="margin-bottom: 15px;">
                        <button onclick="verifyResetToken()">Verify Token</button>
                        <button onclick="resetPassword()">Reset Password</button>
                    </div>
                    <div id="reset-confirm-status" class="status"></div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🧪 API Testing</h2>
            <p>Test various endpoints:</p>
            <div class="endpoint-test">
                <button onclick="testEndpoint('/public')">Public Endpoint</button>
                <button onclick="testEndpoint('/protected')">Protected Endpoint</button>
                <button onclick="testEndpoint('/optional')">Optional Auth</button>
                <button onclick="testEndpoint('/bearer-only')">Bearer Only</button>
                <button onclick="testEndpoint('/token-info')">Token Info</button>
                <button onclick="testEndpoint('/auth/user')">Get User</button>
                <button onclick="testEndpoint('/auth/session')">Get Session</button>
            </div>
            <div id="response" class="response"></div>
        </div>
    </div>

    <script>
        // Server-side rendered user data
        const serverUserData = __USER_DATA__;
        let currentUser = serverUserData.user;

        // Check if user is logged in on page load
        window.onload = function() {
            if (serverUserData.authenticated) {
                showUserStatus(serverUserData.user, serverUserData.auth_source);
            } else {
                hideUserStatus();
            }
        };

        async function checkUserStatus() {
            try {
                const response = await fetch('/auth/user', {
                    credentials: 'include'
                });
                if (response.ok) {
                    const userData = await response.json();
                    currentUser = userData.user;
                    // For dynamically fetched user data, we need to determine auth source
                    // Check if there's a Bearer token in any requests or assume cookie-based
                    const authSource = 'Session Cookie'; // Default assumption for fetch with credentials
                    showUserStatus(userData.user, authSource);
                } else {
                    hideUserStatus();
                }
            } catch (error) {
                console.error('Error checking user status:', error);
                hideUserStatus();
            }
        }

        function showUserStatus(user, authSource) {
            const userStatus = document.getElementById('user-status');
            const userDetails = document.getElementById('user-details');
            userStatus.style.display = 'block';
            userDetails.innerHTML = `
                <p><strong>Email:</strong> ${user.email}</p>
                <p><strong>ID:</strong> ${user.id}</p>
                <p><strong>Email Verified:</strong> ${user.email_verified ? 'Yes' : 'No'}</p>
                <p><strong>Created:</strong> ${new Date(user.created_at).toLocaleString()}</p>
                <p><strong>Auth Source:</strong> ${authSource || 'Unknown'}</p>
            `;
        }

        function hideUserStatus() {
            document.getElementById('user-status').style.display = 'none';
            currentUser = null;
        }

        async function register() {
            const email = document.getElementById('register-email').value;
            const password = document.getElementById('register-password').value;
            const statusDiv = document.getElementById('register-status');

            if (!email || !password) {
                showStatus(statusDiv, 'Please enter both email and password', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/register', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (response.ok) {
                    showStatus(statusDiv, 'Registration successful! You are now logged in.', 'success');
                    document.getElementById('register-email').value = '';
                    document.getElementById('register-password').value = '';
                    checkUserStatus();
                } else {
                    showStatus(statusDiv, data.message || 'Registration failed', 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        async function login() {
            const email = document.getElementById('login-email').value;
            const password = document.getElementById('login-password').value;
            const statusDiv = document.getElementById('login-status');

            if (!email || !password) {
                showStatus(statusDiv, 'Please enter both email and password', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email, password }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (response.ok) {
                    showStatus(statusDiv, 'Login successful!', 'success');
                    document.getElementById('login-email').value = '';
                    document.getElementById('login-password').value = '';
                    checkUserStatus();
                } else {
                    showStatus(statusDiv, data.message || 'Login failed', 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        async function logout() {
            try {
                const response = await fetch('/auth/logout', {
                    method: 'POST',
                    credentials: 'include'
                });

                if (response.ok) {
                    hideUserStatus();
                    document.getElementById('response').textContent = 'Logged out successfully';
                } else {
                    document.getElementById('response').textContent = 'Logout failed';
                }
            } catch (error) {
                document.getElementById('response').textContent = 'Network error: ' + error.message;
            }
        }

        async function requestMagicLink() {
            const email = document.getElementById('magic-email').value;
            const statusDiv = document.getElementById('magic-status');

            if (!email) {
                showStatus(statusDiv, 'Please enter an email address', 'error');
                return;
            }

            try {
                const response = await fetch('/magic-link', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (data.success) {
                    showStatus(statusDiv, data.message, 'success');
                    if (data.magic_token) {
                        showStatus(statusDiv, data.message + '\nMagic link: /magic-link/' + data.magic_token, 'success');
                    }
                } else {
                    showStatus(statusDiv, data.message, 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        async function testEndpoint(endpoint) {
            const responseDiv = document.getElementById('response');
            responseDiv.textContent = 'Loading...';

            try {
                const response = await fetch(endpoint, {
                    credentials: 'include'
                });

                const data = await response.json();
                responseDiv.textContent = `Status: ${response.status}\n\n${JSON.stringify(data, null, 2)}`;
            } catch (error) {
                responseDiv.textContent = `Error: ${error.message}`;
            }
        }

        async function requestPasswordReset() {
            const email = document.getElementById('reset-email').value;
            const statusDiv = document.getElementById('reset-request-status');

            if (!email) {
                showStatus(statusDiv, 'Please enter an email address', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/password/reset/request', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (response.ok) {
                    showStatus(statusDiv, data.message, 'success');
                    document.getElementById('reset-email').value = '';
                } else {
                    showStatus(statusDiv, data.message || 'Password reset request failed', 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        async function verifyResetToken() {
            const token = document.getElementById('reset-token').value;
            const statusDiv = document.getElementById('reset-confirm-status');

            if (!token) {
                showStatus(statusDiv, 'Please enter a reset token', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/password/reset/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (response.ok) {
                    if (data.valid) {
                        showStatus(statusDiv, 'Token is valid! You can now reset your password.', 'success');
                    } else {
                        showStatus(statusDiv, 'Token is invalid or has expired.', 'error');
                    }
                } else {
                    showStatus(statusDiv, 'Failed to verify token', 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        async function resetPassword() {
            const token = document.getElementById('reset-token').value;
            const newPassword = document.getElementById('new-password').value;
            const statusDiv = document.getElementById('reset-confirm-status');

            if (!token || !newPassword) {
                showStatus(statusDiv, 'Please enter both token and new password', 'error');
                return;
            }

            try {
                const response = await fetch('/auth/password/reset/confirm', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ token, new_password: newPassword }),
                    credentials: 'include'
                });

                const data = await response.json();

                if (response.ok) {
                    showStatus(statusDiv, 'Password reset successfully! You can now log in with your new password.', 'success');
                    document.getElementById('reset-token').value = '';
                    document.getElementById('new-password').value = '';
                    checkUserStatus(); // Update user status in case they're now logged in
                } else {
                    showStatus(statusDiv, data.message || 'Password reset failed', 'error');
                }
            } catch (error) {
                showStatus(statusDiv, 'Network error: ' + error.message, 'error');
            }
        }

        function showStatus(element, message, type) {
            element.textContent = message;
            element.className = `status ${type}`;
            element.style.display = 'block';

            // Hide after 5 seconds
            setTimeout(() => {
                element.style.display = 'none';
            }, 5000);
        }
    </script>
</body>
</html>
    "#;

    let html = html_template.replace("__USER_DATA__", &user_data);
    Html(html)
}

async fn public_handler() -> Json<Value> {
    Json(json!({
        "message": "This is a public endpoint - no authentication required",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn protected_handler(user: AuthUser) -> Json<Value> {
    info!("Protected endpoint accessed by user: {}", user.0.id);

    Json(json!({
        "message": "This is a protected endpoint - authentication required",
        "user": {
            "id": user.0.id,
            "email": user.0.email,
            "email_verified": user.0.is_email_verified(),
            "created_at": user.0.created_at
        },
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

async fn optional_auth_handler(user: OptionalAuthUser) -> Json<Value> {
    match user.0 {
        Some(user) => {
            info!(
                "Optional auth endpoint accessed by authenticated user: {}",
                user.id
            );
            Json(json!({
                "message": "This endpoint supports optional authentication",
                "authenticated": true,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "email_verified": user.is_email_verified(),
                    "created_at": user.created_at
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
        None => {
            warn!("Optional auth endpoint accessed by anonymous user");
            Json(json!({
                "message": "This endpoint supports optional authentication",
                "authenticated": false,
                "user": null,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    }
}

async fn bearer_only_handler(bearer_token: SessionTokenFromBearer) -> Json<Value> {
    match bearer_token.0 {
        Some(token) => {
            info!(
                "Bearer-only endpoint accessed with token: {}",
                token.as_str()
            );
            Json(json!({
                "message": "This endpoint accepts Bearer tokens only",
                "authenticated": true,
                "token_received": true,
                "token": token.as_str(),
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
        None => {
            warn!("Bearer-only endpoint accessed without Bearer token");
            Json(json!({
                "message": "This endpoint requires a Bearer token",
                "authenticated": false,
                "token_received": false,
                "error": "Authorization header with Bearer token required",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    }
}

async fn token_info_handler(token_from_request: SessionTokenFromRequest) -> Json<Value> {
    match token_from_request.0 {
        Some(token) => {
            info!(
                "Token info endpoint accessed with token: {}",
                token.as_str()
            );
            Json(json!({
                "message": "Token information endpoint",
                "authenticated": true,
                "token_received": true,
                "token": token.as_str(),
                "note": "This endpoint accepts both Bearer tokens and cookies",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
        None => {
            warn!("Token info endpoint accessed without any token");
            Json(json!({
                "message": "Token information endpoint",
                "authenticated": false,
                "token_received": false,
                "note": "This endpoint accepts both Bearer tokens and cookies",
                "error": "No token provided via Authorization header or cookie",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
        }
    }
}

// Request/Response types for additional endpoints
#[derive(Deserialize)]
struct MagicLinkRequest {
    email: String,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    magic_token: Option<String>,
}

// Handler for requesting magic link
async fn request_magic_link_handler(
    State(torii): State<Arc<Torii<torii::seaorm::SeaORMRepositoryProvider>>>,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Json<ApiResponse>, StatusCode> {
    // Example of how magic link would work when storage backend is implemented
    match torii
        .magic_link()
        .send_link(&req.email, "http://localhost:3000/magic-link")
        .await
    {
        Ok(token) => {
            info!("Magic link generated for email: {}", req.email);
            Ok(Json(ApiResponse {
                success: true,
                message:
                    "Magic link sent! Check your email (or ./emails/ directory in this example)."
                        .to_string(),
                user_id: None,
                session_token: None,
                magic_token: Some(token.token), // In production, don't return the actual token
            }))
        }
        Err(e) => {
            warn!("Failed to generate magic link: {}", e);
            Ok(Json(ApiResponse {
                success: false,
                message: format!(
                    "Magic link functionality requires full implementation in storage backend: {e}"
                ),
                user_id: None,
                session_token: None,
                magic_token: None,
            }))
        }
    }
}

// Handler for verifying magic link
async fn verify_magic_link_handler(
    State(torii): State<Arc<Torii<torii::seaorm::SeaORMRepositoryProvider>>>,
    Path(token): Path<String>,
) -> Result<Json<ApiResponse>, StatusCode> {
    // Note: Magic link functionality requires full implementation in storage backend
    info!("Magic link verification attempt for token: {}", token);

    match torii.magic_link().authenticate(&token, None, None).await {
        Ok((user, session)) => Ok(Json(ApiResponse {
            success: true,
            message: "Magic link verified successfully.".to_string(),
            user_id: Some(user.id.to_string()),
            session_token: Some(session.token.to_string()),
            magic_token: None,
        })),
        Err(e) => {
            warn!("Failed to verify magic link: {}", e);
            Ok(Json(ApiResponse {
                success: false,
                message: format!("Failed to verify magic link: {e}"),
                user_id: None,
                session_token: None,
                magic_token: None,
            }))
        }
    }
}
