use torii::{ToriiBuilder, JwtConfig};
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create JWT configuration with HS256 algorithm
    // The secret must be at least 32 bytes for security
    let jwt_config = JwtConfig::new_hs256(
        b"your-secret-key-at-least-32-chars-long!".to_vec()
    )?
        .with_issuer("your-app-name")
        .with_metadata(true);

    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .with_jwt_sessions(jwt_config)
        .with_session_expiry(Duration::hours(2))
        .apply_migrations(true)
        .build()
        .await?;

    Ok(())
}
