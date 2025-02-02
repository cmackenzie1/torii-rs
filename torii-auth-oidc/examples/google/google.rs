use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use serde::Deserialize;
use sqlx::{Pool, Sqlite};
use torii_auth_oidc::{AuthFlowCallback, OIDCPlugin};
use torii_core::plugin::PluginManager;

#[derive(Debug, Deserialize)]
struct QueryParams {
    code: String,
    state: String,
}

#[derive(Clone)]
struct AppState {
    pool: Pool<Sqlite>,
    plugin_manager: Arc<PluginManager>,
}

#[axum::debug_handler]
async fn login_handler(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, Redirect) {
    let plugin = state.plugin_manager.get_plugin::<OIDCPlugin>().unwrap();
    let auth_flow = plugin
        .begin_auth(
            &state.pool,
            "http://localhost:4000/auth/google/callback".to_string(),
        )
        .await
        .unwrap();

    let jar = jar.add(
        Cookie::build(("csrf_state", auth_flow.csrf_state))
            .path("/")
            .http_only(true),
    );
    let jar = jar.add(
        Cookie::build(("nonce_key", auth_flow.nonce_key))
            .path("/")
            .http_only(true),
    );

    (jar, Redirect::to(&auth_flow.redirect_uri))
}

#[axum::debug_handler]
async fn callback_handler(
    State(state): State<AppState>,
    Query(params): Query<QueryParams>,
    jar: CookieJar,
) -> impl IntoResponse {
    let nonce_key = jar.get("nonce_key").unwrap().value();

    let plugin = state.plugin_manager.get_plugin::<OIDCPlugin>().unwrap();
    let user = plugin
        .callback(
            &state.pool,
            &AuthFlowCallback {
                csrf_state: params.state,
                nonce_key: nonce_key.to_string(),
                code: params.code,
            },
        )
        .await
        .unwrap();

    Json(user)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite:./google.db?mode=rwc")
        .await
        .unwrap();

    let mut plugin_manager = PluginManager::new();
    plugin_manager.register(OIDCPlugin::new(
        "google".to_string(),
        std::env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID must be set"),
        std::env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET must be set"),
        "http://localhost:4000/auth/google/callback".to_string(),
    ));
    plugin_manager.setup(&pool).await.unwrap();
    plugin_manager.migrate(&pool).await.unwrap();

    let app = Router::new()
        .route("/", get(|| async { "Hello, World!" }))
        .route("/auth/google/login", get(login_handler))
        .route("/auth/google/callback", get(callback_handler))
        .with_state(AppState {
            pool,
            plugin_manager: Arc::new(plugin_manager),
        });

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:4000").await.unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        axum::serve(listener, app).await.unwrap();
    });

    println!(
        "Please open the following URL in your browser: http://localhost:4000/auth/google/login"
    );

    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
