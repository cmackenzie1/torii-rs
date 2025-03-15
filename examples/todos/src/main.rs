use dashmap::DashMap;
use std::{net::SocketAddr, sync::Arc};
use torii::{SeaORMStorage, Torii};

mod routes;
mod templates;

/// Application state shared between route handlers
/// Contains references to:
/// - torii: Coordinates authentication plugins
#[derive(Clone)]
pub(crate) struct AppState {
    torii: Arc<Torii<SeaORMStorage>>,
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

    // Create a new storage instance for our application
    let storage = Arc::new(
        SeaORMStorage::connect("sqlite://todos.db?mode=rwc")
            .await
            .expect("Failed to connect to database"),
    );

    // Migrate the storage schema
    storage.migrate().await.expect("Failed to migrate storage");

    // For demonstration, we can use different approaches:

    // 1. Simplest approach with a single storage backend
    let torii = Torii::new(storage).with_password_plugin();

    // Alternative Options:
    //
    // 2. If you want separate storage for sessions (e.g., Redis):
    // let user_storage = storage.clone();
    // let session_storage = Arc::new(RedisStorage::connect("redis://localhost").await.unwrap());
    // let torii = Torii::with_storages(user_storage, session_storage).with_password_plugin();
    //
    // 3. If you need custom managers for additional behavior:
    // let user_manager: Arc<dyn UserManager + Send + Sync> = Arc::new(CustomUserManager::new(storage.clone()));
    // let session_manager: Arc<dyn SessionManager + Send + Sync> = Arc::new(DefaultSessionManager::new(storage.clone()));
    // let torii = Torii::with_managers(storage.clone(), storage.clone(), user_manager, session_manager);
    //
    // 4. If your managers fully encapsulate their storage and you don't need plugins:
    // let user_manager: Arc<dyn UserManager + Send + Sync> = Arc::new(MyUserManager::new(my_db_conn.clone()));
    // let session_manager: Arc<dyn SessionManager + Send + Sync> = Arc::new(RedisSessionManager::new("redis://localhost"));
    // let torii = Torii::<()>::with_custom_managers(user_manager, session_manager);

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
