use std::sync::Arc;

use axum::{
    Form, Json, Router,
    body::Body,
    extract::{Request, State},
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
use torii_auth_password::PasswordPlugin;
use torii_core::{
    Session,
    plugin::PluginManager,
    session::SessionId,
    storage::{SessionStorage, UserStorage},
};
use torii_storage_sqlite::SqliteStorage;

/// This example demonstrates how to set up a basic email/password authentication system using Torii.
/// It creates a simple web server with:
/// - Sign up page (/sign-up)
/// - Sign in page (/sign-in)
/// - Protected route (/whoami) that shows the authenticated user's details
///
/// The example uses:
/// - SQLite for storing users and sessions (in memory database)
/// - Axum web framework for routing and handling requests
/// - EmailPasswordPlugin from torii-auth-password for authentication logic
///
/// Key concepts demonstrated:
/// - Setting up storage backends (SqliteStorage)
/// - Configuring the plugin system (PluginManager)
/// - Session-based authentication with cookies
/// - Protected routes using middleware
#[derive(Deserialize)]
struct SignUpForm {
    email: String,
    password: String,
}

/// Form data for user registration
#[derive(Deserialize)]
struct SignInForm {
    email: String,
    password: String,
}

/// Application state shared between route handlers
/// Contains references to:
/// - plugin_manager: Coordinates authentication plugins
#[derive(Clone)]
struct AppState {
    plugin_manager: Arc<PluginManager<SqliteStorage, SqliteStorage>>,
}

/// Handles user registration
/// 1. Extracts email/password from form submission
/// 2. Creates new user via EmailPasswordPlugin
/// 3. Redirects to sign-in page on success
#[axum::debug_handler]
async fn sign_up_form_handler(
    State(state): State<AppState>,
    Form(params): Form<SignUpForm>,
) -> impl IntoResponse {
    let plugin = state
        .plugin_manager
        .get_plugin::<PasswordPlugin<SqliteStorage>>("email_password")
        .unwrap();

    match plugin
        .register_user_with_password(&params.email, &params.password, None)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Successfully signed up" })),
        )
            .into_response(),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Sign up failed")
            })),
        )
            .into_response(),
    }
}

/// Handles user authentication
/// 1. Validates email/password credentials
/// 2. Creates a new session if valid
/// 3. Sets session cookie and redirects to protected area
#[axum::debug_handler]
async fn sign_in_form_handler(
    State(state): State<AppState>,
    Form(params): Form<SignInForm>,
) -> impl IntoResponse {
    let plugin: Arc<PasswordPlugin<SqliteStorage>> = state
        .plugin_manager
        .get_plugin::<PasswordPlugin<SqliteStorage>>("email_password")
        .unwrap();

    let user = plugin
        .login_user_with_password(&params.email, &params.password)
        .await
        .unwrap();

    let session = state
        .plugin_manager
        .session_storage()
        .create_session(&Session::builder().user_id(user.id.clone()).build().unwrap())
        .await
        .unwrap();

    let cookie = Cookie::build(("session_id", session.id.to_string()))
        .path("/")
        .http_only(true)
        .secure(false) // TODO: Set to true in production
        .same_site(SameSite::Lax);
    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie.to_string())],
        Json(json!({ "message": "Successfully signed in" })),
    )
        .into_response()
}

#[axum::debug_handler]
async fn sign_up_handler() -> impl IntoResponse {
    Html(
        r#"
        <h1>Sign Up</h1>
    <form action="/auth/sign-up" method="post">
        <input type="email" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Sign Up</button>
    </form>
    "#,
    )
}

#[axum::debug_handler]
async fn sign_in_handler() -> impl IntoResponse {
    Html(
        r#"
        <h1>Sign In</h1>
    <form action="/auth/sign-in" method="post">
        <input type="email" name="email" placeholder="Email">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Sign In</button>
    </form>
    "#,
    )
}

/// Middleware to protect routes that require authentication
/// Checks for valid session cookie and redirects to sign-in if missing/invalid
async fn verify_session<B>(
    State(state): State<AppState>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        // Verify session exists and is valid
        state
            .plugin_manager
            .session_storage()
            .get_session(&SessionId::new(&session_id))
            .await
            .unwrap();

        return next.run(request).await;
    }

    // If session is invalid or missing, redirect to sign in
    Redirect::to("/sign-in").into_response()
}

/// Protected route that displays the currently authenticated user's details
/// Returns 401 if not authenticated
async fn whoami_handler(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        let session = state
            .plugin_manager
            .session_storage()
            .get_session(&SessionId::new(&session_id))
            .await
            .unwrap();

        let user = state
            .plugin_manager
            .user_storage()
            .get_user(&session.unwrap().user_id)
            .await
            .unwrap();
        return Json(user).into_response();
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "Not authenticated"
        })),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite::memory:").await.unwrap();

    let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
    let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

    user_storage.migrate().await.unwrap();
    session_storage.migrate().await.unwrap();

    let mut plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());
    plugin_manager.register_plugin(PasswordPlugin::new(user_storage.clone()));
    let plugin_manager = Arc::new(plugin_manager);

    let app_state = AppState {
        plugin_manager: plugin_manager.clone(),
    };

    let app = Router::new()
        .route("/whoami", get(whoami_handler))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            verify_session::<Body>,
        ))
        .route("/", get(|| async { "Hello, World!" }))
        .route("/sign-up", get(sign_up_handler))
        .route("/sign-in", get(sign_in_handler))
        .route("/auth/sign-up", post(sign_up_form_handler))
        .route("/auth/sign-in", post(sign_in_form_handler))
        .with_state(app_state.clone());

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    });

    println!("Please open the following URL in your browser: http://localhost:4000/sign-up");

    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
