use dashmap::DashMap;
use std::{net::SocketAddr, sync::Arc};
use torii::{SeaORMStorage, Torii};

mod routes;
mod templates;

/// Application state shared between route handlers
/// Contains references to:
/// - plugin_manager: Coordinates authentication plugins
#[derive(Clone)]
pub(crate) struct AppState {
    torii: Arc<Torii<SeaORMStorage, SeaORMStorage>>,
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

    let user_storage = Arc::new(
        SeaORMStorage::connect("sqlite://todos.db?mode=rwc")
            .await
            .expect("Failed to connect to database"),
    );
    let session_storage = Arc::new(
        SeaORMStorage::connect("sqlite://todos.db?mode=rwc")
            .await
            .expect("Failed to connect to database"),
    );

    // TODO: Move this into a torii init function
    user_storage
        .migrate()
        .await
        .expect("Failed to migrate user storage");
    session_storage
        .migrate()
        .await
        .expect("Failed to migrate session storage");

    let torii = Torii::new(user_storage, session_storage).with_password_plugin();

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
