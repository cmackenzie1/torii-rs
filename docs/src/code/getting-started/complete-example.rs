use std::sync::Arc;
use torii::ToriiBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Torii instance using the builder pattern
    let torii = Arc::new(
        ToriiBuilder::new()
            .with_seaorm("sqlite://auth.db?mode=rwc")
            .await?
            .apply_migrations(true)
            .build()
            .await?
    );

    // Register a user
    let user = torii.password().register("user@example.com", "secure_password").await?;
    println!("User registered: {}", user.id);

    // Login and create session
    let (user, session) = torii.password().authenticate(
        "user@example.com",
        "secure_password",
        Some("Mozilla/5.0 (compatible browser)".to_string()),
        Some("192.168.1.100".to_string())
    ).await?;

    println!("Login successful!");
    println!("User: {}", user.id);
    println!("Session token: {}", session.token);

    // Validate session
    let validated_session = torii.get_session(&session.token).await?;
    println!("Session valid for user: {}", validated_session.user_id);

    Ok(())
}