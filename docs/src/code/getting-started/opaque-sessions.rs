use torii::ToriiBuilder;
use chrono::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Opaque sessions are the default - sessions are stored in the database
    let torii = ToriiBuilder::new()
        .with_sqlite("sqlite::memory:")
        .await?
        .with_session_expiry(Duration::days(30))
        .apply_migrations(true)
        .build()
        .await?;

    Ok(())
}
