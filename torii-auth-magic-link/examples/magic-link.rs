use std::sync::Arc;

use axum::{
    Form, Json, Router,
    extract::{Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::{
    CookieJar,
    cookie::{Cookie, SameSite},
};
use serde::Deserialize;
use serde_json::json;
use sqlx::{Pool, Sqlite};
use torii_auth_magic_link::MagicLinkPlugin;
use torii_core::{
    DefaultUserManager, Session,
    plugin::PluginManager,
    session::SessionToken,
    storage::{SessionStorage, UserStorage},
};
use torii_storage_sqlite::SqliteStorage;

/// This example demonstrates how to set up a basic magic link authentication system using Torii.
/// It creates a simple web server with:
/// - Sign up page (/)
/// - Magic link verification route (/auth/magic-link/verify)
/// - Magic link generation route (/auth/magic-link/generate)
/// - Protected route (/whoami) that shows the authenticated user's details
///
/// The example uses:
/// - SQLite for storing users and sessions (in memory database)
/// - Axum web framework for routing and handling requests
/// - MagicLinkPlugin from torii-auth-magic-link for authentication logic
///
/// Key concepts demonstrated:
/// - Setting up storage backends (SqliteStorage)
/// - Configuring the plugin system (PluginManager)
/// - Session-based authentication with cookies
/// - Protected routes using middleware
#[derive(Deserialize)]
struct SignUpForm {
    email: String,
}

/// Form data for user registration
#[derive(Deserialize)]
struct SignInParams {
    token: String,
}

/// Application state shared between route handlers
/// Contains references to:
/// - plugin_manager: Coordinates authentication plugins
#[derive(Clone)]
struct AppState {
    plugin_manager: Arc<PluginManager<SqliteStorage, SqliteStorage>>,
}

/// Handles user registration
/// 1. Extracts email from form submission
/// 2. Creates new user via MagicLinkPlugin
/// 3. Displays magic link to user (for demonstration purposes only). After generating the link,
/// you should send it to the user's email.
#[axum::debug_handler]
async fn generate_magic_link_handler(
    State(state): State<AppState>,
    Form(params): Form<SignUpForm>,
) -> impl IntoResponse {
    let plugin = state
        .plugin_manager
        .get_plugin::<MagicLinkPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>(
            "magic_link",
        )
        .unwrap();

    let token = plugin.generate_magic_token(&params.email).await.unwrap();
    let link = format!(
        "http://localhost:4000/auth/magic-link/verify?token={}",
        token.token
    );

    (
        StatusCode::OK,
        // NOTE: DO NOT DO THIS IN PRODUCTION. THIS IS ONLY FOR DEMONSTRATION PURPOSES.
        Html(format!(
            r#"
            <div style="max-width: 600px; margin: 40px auto; padding: 20px; font-family: sans-serif;">
                <div style="padding: 15px; background-color: #fff3cd; border: 1px solid #ffeeba; border-radius: 4px; margin-bottom: 20px;">
                    <strong>⚠️ WARNING:</strong> Displaying magic links directly in the response is insecure and should never be done in production.
                </div>
                <div style="text-align: center;">
                    <p>For demonstration only:</p>
                    <p>Please click the following link to sign in:</p>
                    <a href='{}' style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 4px;">{}</a>
                </div>
            </div>
            "#,
            link, link
        )),
    )
        .into_response()
}

/// Handles user authentication
/// 1. Validates magic link token
/// 2. Creates a new session if valid
/// 3. Sets session cookie and redirects to protected area
#[axum::debug_handler]
async fn verify_magic_link_handler(
    State(state): State<AppState>,
    Query(params): Query<SignInParams>,
) -> impl IntoResponse {
    let plugin = state
        .plugin_manager
        .get_plugin::<MagicLinkPlugin<DefaultUserManager<SqliteStorage>, SqliteStorage>>(
            "magic_link",
        )
        .unwrap();

    // This verifies the magic token, marks it as used, and returns the user
    let user = plugin.verify_magic_token(&params.token).await.unwrap();

    let session = state
        .plugin_manager
        .session_storage()
        .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
        .await
        .expect("create_session failed");

    let cookie = Cookie::build(("session_id", session.token.to_string()))
        .path("/")
        .http_only(true)
        .secure(false) // TODO: Set to true in production
        .same_site(SameSite::Lax);
    (
        [(header::SET_COOKIE, cookie.to_string())],
        Redirect::to("/whoami"),
    )
        .into_response()
}

/// Middleware to protect routes that require authentication
/// Checks for valid session cookie and redirects to sign-in if missing/invalid
async fn verify_session(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if session_id.is_none() {
        return Redirect::to("/sign-in").into_response();
    }

    // Verify session exists and is valid
    state
        .plugin_manager
        .session_storage()
        .get_session(&SessionToken::new(
            &session_id.expect("session_id is required"),
        ))
        .await
        .unwrap();

    next.run(request).await
}

/// Protected route that displays the currently authenticated user's details
/// Returns 401 if not authenticated
async fn whoami_handler(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if session_id.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "Not authenticated"
            })),
        )
            .into_response();
    }

    let session = state
        .plugin_manager
        .session_storage()
        .get_session(&SessionToken::new(
            &session_id.expect("session_id is required"),
        ))
        .await
        .unwrap();

    let user = state
        .plugin_manager
        .user_storage()
        .get_user(&session.unwrap().user_id)
        .await
        .unwrap();

    Json(user).into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();

    let storage = Arc::new(SqliteStorage::new(pool.clone()));
    let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

    storage.migrate().await.unwrap();
    session_storage.migrate().await.unwrap();

    // Create user manager
    let user_manager = Arc::new(DefaultUserManager::new(storage.clone()));

    let mut plugin_manager = PluginManager::new(storage.clone(), session_storage.clone());
    plugin_manager.register_plugin(MagicLinkPlugin::new(user_manager, storage.clone()));
    let plugin_manager = Arc::new(plugin_manager);

    let app_state = AppState {
        plugin_manager: plugin_manager.clone(),
    };

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            verify_session,
        ))
        .route(
            "/",
            get(|| async {
                Html(
                    r#"
                <h1>Magic Link</h1>
                <form action="/auth/magic-link/generate" method="post">
                    <input type="email" name="email" placeholder="Email">
                    <button type="submit">Get Magic Link</button>
                </form>
                "#,
                )
            }),
        )
        .route(
            "/auth/magic-link/generate",
            post(generate_magic_link_handler),
        )
        .route("/auth/magic-link/verify", get(verify_magic_link_handler))
        .with_state(app_state.clone());

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    });

    println!("Please open the following URL in your browser: http://localhost:4000/");

    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
