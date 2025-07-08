use std::sync::Arc;

use axum::{response::Json, routing::get, Router};
use serde_json::{json, Value};
use torii::Torii;
use torii_axum::{
    AuthUser, CookieConfig, OptionalAuthUser, SessionTokenFromBearer, SessionTokenFromRequest,
};
use torii_storage_seaorm::SeaORMStorage;
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

    // Create repository provider and Torii instance
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Arc::new(Torii::new(repositories));

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

    // Create the main application
    let app = Router::new()
        .nest("/auth", auth_routes)
        .route("/", get(index_handler))
        .route("/public", get(public_handler))
        .route("/protected", get(protected_handler))
        .route("/optional", get(optional_auth_handler))
        .route("/bearer-only", get(bearer_only_handler))
        .route("/token-info", get(token_info_handler))
        .layer(axum::middleware::from_fn_with_state(
            auth_state,
            torii_axum::auth_middleware,
        ))
        .layer(axum::Extension(cookie_config));

    info!("Server starting on http://localhost:3000");
    info!("Available endpoints:");
    info!("  GET  /                    - Index page");
    info!("  GET  /public              - Public endpoint");
    info!("  GET  /protected           - Protected endpoint (requires authentication)");
    info!("  GET  /optional            - Optional authentication endpoint");
    info!("  GET  /bearer-only         - Bearer token only endpoint");
    info!("  GET  /token-info          - Token information endpoint");
    info!("  POST /auth/register       - Register new user");
    info!("  POST /auth/login          - Login user");
    info!("  POST /auth/password       - Change password");
    info!("  GET  /auth/user           - Get current user");
    info!("  GET  /auth/session        - Get current session");
    info!("  POST /auth/logout         - Logout user");
    info!("  GET  /auth/health         - Health check");

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn index_handler() -> Json<Value> {
    Json(json!({
        "message": "Welcome to Torii Axum SQLite Password Example",
        "endpoints": {
            "public": "/public",
            "protected": "/protected",
            "optional": "/optional",
            "bearer_only": "/bearer-only",
            "token_info": "/token-info",
            "auth": {
                "register": "POST /auth/register",
                "login": "POST /auth/login",
                "password": "POST /auth/password",
                "user": "GET /auth/user",
                "session": "GET /auth/session",
                "logout": "POST /auth/logout",
                "health": "GET /auth/health"
            }
        },
        "example_usage": {
            "register": {
                "method": "POST",
                "url": "/auth/register",
                "body": {
                    "email": "user@example.com",
                    "password": "securepassword123"
                }
            },
            "login": {
                "method": "POST",
                "url": "/auth/login",
                "body": {
                    "email": "user@example.com",
                    "password": "securepassword123"
                }
            },
            "bearer_auth": {
                "method": "GET",
                "url": "/bearer-only",
                "headers": {
                    "Authorization": "Bearer <session_token>"
                }
            }
        }
    }))
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
