use dashmap::DashMap;
use std::{net::SocketAddr, sync::Arc};
use torii::{Torii, SqliteRepositoryProvider};
use torii_core::repositories::RepositoryProvider;

mod routes;
mod templates;

/// Application state shared between route handlers
/// Contains references to:
/// - torii: Coordinates authentication services
#[derive(Clone)]
pub(crate) struct AppState {
    torii: Arc<Torii<SqliteRepositoryProvider>>,
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

    // Create SQLite connection pool
    let pool = sqlx::SqlitePool::connect("sqlite://todos.db?mode=rwc")
        .await
        .expect("Failed to connect to database");

    // Create repository provider
    let repositories = SqliteRepositoryProvider::new(pool);

    // Run migrations
    repositories.migrate().await.expect("Failed to migrate storage");

    // Create Torii instance with repositories
    let torii = Torii::new(Arc::new(repositories));

    let app_state = AppState {
        torii: Arc::new(torii),
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
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("Server error");
    });

    println!("Please open the following URL in your browser: http://localhost:4000/");
    println!("Press Enter or Ctrl+C to exit...");
    let _ = std::io::stdin().read_line(&mut String::new());
}
