use std::sync::Arc;
use axum::{response::Json, routing::get, Router};
use torii::Torii;
use torii_axum::{AuthUser, CookieConfig};
use torii_storage_seaorm::SeaORMStorage;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set up database and Torii
    let storage = SeaORMStorage::connect("sqlite::memory:").await?;
    storage.migrate().await?;
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Arc::new(Torii::new(repositories));

    // Create authentication routes with cookie configuration
    let auth_routes = torii_axum::routes(torii.clone())
        .with_cookie_config(CookieConfig::development())
        .build();

    // Build your application with auth routes
    let app = Router::new()
        .nest("/auth", auth_routes)
        .route("/protected", get(protected_handler))
        .with_state(torii);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// Protected route handler
async fn protected_handler(user: AuthUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "user_id": user.id,
        "email": user.email
    }))
}