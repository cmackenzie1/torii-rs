use std::sync::Arc;
use torii::{Torii, JwtConfig, SessionConfig};
use torii_storage_seaorm::SeaORMStorage;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up SeaORM storage with PostgreSQL
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://user:password@localhost/torii_db".to_string());

    let storage = SeaORMStorage::connect(&database_url).await?;
    storage.migrate().await?;

    // Create repository provider
    let repositories = Arc::new(storage.into_repository_provider());

    // Configure JWT sessions
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secret-key-at-least-32-characters-long!".to_string());

    let jwt_config = JwtConfig::new(jwt_secret)
        .with_issuer("my-app")
        .with_metadata(true);

    // Create Torii instance with JWT sessions
    let torii = Arc::new(
        Torii::new(repositories)
            .with_session_config(
                SessionConfig::default()
                    .with_jwt(jwt_config)
                    .expires_in(Duration::hours(24))
            )
    );

    // Example: Register and login a user
    let user = torii.password().register("user@example.com", "secure_password").await?;
    println!("User registered: {}", user.id);

    let (login_user, session) = torii.password().authenticate(
        "user@example.com",
        "secure_password",
        Some("Mozilla/5.0 (compatible browser)".to_string()),
        Some("192.168.1.100".to_string())
    ).await?;

    println!("Login successful!");
    println!("JWT Token: {}", session.token);

    // Validate the JWT session
    let validated_session = torii.get_session(&session.token).await?;
    println!("Session valid for user: {}", validated_session.user_id);

    Ok(())
}