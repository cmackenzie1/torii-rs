use torii::ToriiBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create Torii using the builder pattern
    // This connects to SQLite and applies migrations automatically
    let torii = ToriiBuilder::new()
        .with_seaorm("sqlite::memory:")
        .await?
        .apply_migrations(true)
        .build()
        .await?;

    // Now torii is ready to use for authentication
    Ok(())
}
