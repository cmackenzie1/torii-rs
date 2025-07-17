use std::sync::Arc;
use torii::Torii;
use torii_storage_seaorm::SeaORMStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the database connection
    let storage = SeaORMStorage::connect("sqlite::memory:").await?;

    // Run migrations to set up the database schema
    storage.migrate().await?;

    // Create repository provider and Torii instance
    let repositories = Arc::new(storage.into_repository_provider());
    let torii = Arc::new(Torii::new(repositories));

    // Now torii is ready to use for authentication
    Ok(())
}