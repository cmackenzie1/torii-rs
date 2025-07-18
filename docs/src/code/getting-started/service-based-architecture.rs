use std::sync::Arc;
use torii::Torii;
use torii_storage_seaorm::SeaORMStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up storage backend
    let storage = SeaORMStorage::connect("sqlite://auth.db?mode=rwc").await?;
    storage.migrate().await?;

    // Create repository provider - this is the new pattern
    let repositories = Arc::new(storage.into_repository_provider());

    // Single constructor for all authentication methods
    let torii = Arc::new(Torii::new(repositories));

    // All authentication methods are now available as services
    let user = torii.password().register("user@example.com", "password").await?;
    let (_user, session) = torii.password().authenticate("user@example.com", "password", None, None).await?;

    Ok(())
}