use std::sync::Arc;
use torii::{ToriiBuilder, JwtConfig};
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get database URL from environment
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://user:password@localhost/torii_db".to_string());

    // Configure JWT sessions
    let jwt_secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secret-key-at-least-32-characters-long!".to_string());

    let jwt_config = JwtConfig::new_hs256(jwt_secret.into_bytes())?
        .with_issuer("my-app")
        .with_metadata(true);

    // Create Torii instance using the builder pattern with PostgreSQL
    let torii = Arc::new(
        ToriiBuilder::new()
            .with_postgres(&database_url)
            .await?
            .with_jwt_sessions(jwt_config)
            .with_session_expiry(Duration::hours(24))
            .apply_migrations(true)
            .build()
            .await?
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