use std::net::SocketAddr;

use askama::Template;
use axum::{
    extract::{ConnectInfo, Form, Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use axum_extra::{
    extract::{
        cookie::{Cookie, SameSite},
        CookieJar,
    },
    headers::UserAgent,
    TypedHeader,
};
use serde::Deserialize;
use serde_json::json;
use torii::{SessionToken, User};
use tracing::info;
use uuid::Uuid;

use crate::{
    templates::{Context, IndexTemplate, SignInTemplate, SignUpTemplate, TodoPartial},
    AppState, Todo,
};

#[derive(Deserialize)]
pub struct SignUpForm {
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct SignInForm {
    email: String,
    password: String,
}

pub fn create_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/sign-up", get(sign_up_handler))
        .route("/sign-in", get(sign_in_handler))
        .route("/sign-out", get(sign_out_handler))
        .route("/auth/sign-up", post(sign_up_form_handler))
        .route("/auth/sign-in", post(sign_in_form_handler))
        .merge(
            Router::new()
                .route("/whoami", get(whoami_handler))
                .route("/todos", post(create_todo_handler))
                .route("/todos/{id}", delete(delete_todo_handler))
                .route("/todos/{id}/toggle", post(toggle_todo_handler))
                .route_layer(middleware::from_fn_with_state(
                    app_state.clone(),
                    verify_session,
                )),
        )
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            add_user_extension,
        ))
        .layer(middleware::from_fn(add_connection_info_extension))
        .with_state(app_state)
}

#[axum::debug_handler]
pub async fn index_handler(
    Extension(user): Extension<Option<User>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let todos: Vec<_> = state
        .todos
        .iter()
        .map(|item| item.value().clone())
        .filter(|todo| todo.user_id == user.as_ref().map(|u| u.id.to_string()).unwrap_or_default())
        .collect();

    let template = IndexTemplate {
        context: Context { user },
        todos,
    };
    let html = template.render().unwrap();
    Html(html)
}

#[axum::debug_handler]
pub async fn sign_up_handler(Extension(user): Extension<Option<User>>) -> impl IntoResponse {
    if let Some(_user) = user {
        return Redirect::to("/").into_response();
    }
    let template = SignUpTemplate {
        context: Context { user },
    };
    let html = template.render().unwrap();
    Html(html).into_response()
}

#[axum::debug_handler]
pub async fn sign_in_handler(Extension(user): Extension<Option<User>>) -> impl IntoResponse {
    if let Some(_user) = user {
        return Redirect::to("/").into_response();
    }
    let template = SignInTemplate {
        context: Context { user },
    };
    let html = template.render().unwrap();
    Html(html).into_response()
}

#[axum::debug_handler]
pub async fn sign_out_handler(jar: CookieJar) -> impl IntoResponse {
    let jar = jar.remove(Cookie::from("session_id"));

    (jar, Redirect::to("/")).into_response()
}

#[derive(Deserialize)]
pub struct CreateTodoForm {
    title: String,
}

#[axum::debug_handler]
pub async fn create_todo_handler(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Form(params): Form<CreateTodoForm>,
) -> Response {
    let todo = Todo {
        id: Uuid::now_v7().to_string(),
        title: params.title,
        completed_at: None,
        user_id: user.id.to_string(),
    };
    state.todos.insert(todo.id.clone(), todo.clone());
    let todo_partial = TodoPartial { todo };
    let html = todo_partial.render().unwrap();
    Html(html).into_response()
}

#[axum::debug_handler]
pub async fn delete_todo_handler(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    state.todos.remove(&id);
    let html = "Todo deleted".into_response();
    Html(html).into_response()
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
    let user = state
        .torii
        .password()
        .register(&params.email, &params.password)
        .await;

    info!("User registered: {:?}", user);

    match user {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "Successfully signed up" })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("Sign up failed: {}", e)
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
    Extension(connection_info): Extension<ConnectionInfo>,
    Form(params): Form<SignInForm>,
) -> impl IntoResponse {
    let user_agent = connection_info.user_agent;
    let ip_address = connection_info.ip;

    let (_, session) = state
        .torii
        .password()
        .authenticate(&params.email, &params.password, user_agent, ip_address)
        .await
        .unwrap();

    let cookie = Cookie::build(("session_id", session.token.to_string()))
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

async fn add_user_extension(
    State(state): State<AppState>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(None::<User>);
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        let session = state
            .torii
            .get_session(&SessionToken::new(&session_id))
            .await
            .expect("Failed to get session");

        let user = state
            .torii
            .get_user(&session.user_id)
            .await
            .expect("Failed to get user");
        // Adding both User and Option<User> so that routes that need a logged in user can
        // use Extension<User>, while routes that support both logged in and out
        // can use Extension<Option<User>>
        request.extensions_mut().insert(user.clone());
        if let Some(valid_user) = user {
            request.extensions_mut().insert(valid_user);
        }
    }
    next.run(request).await
}

async fn verify_session(
    Extension(user): Extension<Option<User>>,
    request: Request,
    next: Next,
) -> Response {
    match user {
        Some(_) => next.run(request).await,
        None => Redirect::to("/sign-in").into_response(),
    }
}

async fn whoami_handler(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session_id = jar
        .get("session_id")
        .and_then(|cookie| cookie.value().parse::<String>().ok());

    if let Some(session_id) = session_id {
        let session = state
            .torii
            .get_session(&SessionToken::new(&session_id))
            .await
            .expect("Failed to get session");

        let user = state
            .torii
            .get_user(&session.user_id)
            .await
            .expect("Failed to get user");

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

#[axum::debug_handler]
async fn toggle_todo_handler(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Some(mut todo) = state.todos.get_mut(&id) {
        if todo.user_id == user.id.to_string() {
            todo.completed_at = match todo.completed_at {
                Some(_) => None,
                None => Some(chrono::Utc::now().to_rfc3339()),
            };
            let todo_partial = TodoPartial { todo: todo.clone() };
            let html = todo_partial.render().unwrap();
            return Html(html).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

#[derive(Clone, Debug)]
struct ConnectionInfo {
    ip: Option<String>,
    user_agent: Option<String>,
}

async fn add_connection_info_extension(
    user_agent: Option<TypedHeader<UserAgent>>,
    addr: ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(ConnectionInfo {
        ip: Some(addr.ip().to_string()),
        user_agent: user_agent.map(|u| u.to_string()),
    });
    next.run(request).await
}
