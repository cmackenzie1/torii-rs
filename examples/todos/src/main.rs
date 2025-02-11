use dashmap::DashMap;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use torii_auth_email::EmailPasswordPlugin;
use torii_core::plugin::PluginManager;
use torii_storage_sqlite::SqliteStorage;

mod routes;
mod templates;

/// Application state shared between route handlers
/// Contains references to:
/// - plugin_manager: Coordinates authentication plugins
#[derive(Clone)]
pub(crate) struct AppState {
    plugin_manager: Arc<PluginManager<SqliteStorage, SqliteStorage>>,
    todos: Arc<DashMap<String, Todo>>,
}

#[derive(Debug, Clone)]
pub struct Todo {
    pub id: String,
    pub title: String,
    pub completed_at: Option<String>,
    pub user_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let pool = Pool::<Sqlite>::connect("sqlite://todos.db?mode=rwc")
        .await
        .expect("Failed to connect to database");

    let user_storage = Arc::new(SqliteStorage::new(pool.clone()));
    let session_storage = Arc::new(SqliteStorage::new(pool.clone()));

    user_storage
        .migrate()
        .await
        .expect("Failed to migrate user storage");
    session_storage
        .migrate()
        .await
        .expect("Failed to migrate session storage");

    let mut plugin_manager = PluginManager::new(user_storage.clone(), session_storage.clone());
    plugin_manager.register(EmailPasswordPlugin::new());
    plugin_manager
        .setup()
        .await
        .expect("Failed to setup plugin manager");
    let plugin_manager = Arc::new(plugin_manager);

    let app_state = AppState {
        plugin_manager: plugin_manager.clone(),
        todos: Arc::new(DashMap::new()),
    };

    let app = routes::create_router(app_state);

    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:4000")
            .await
            .expect("Failed to bind to port");
        println!(
            "Listening on {}",
            listener.local_addr().expect("Failed to get local address")
        );
        axum::serve(listener, app).await.expect("Server error");
    });

    println!("Please open the following URL in your browser: http://localhost:4000/");
    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
