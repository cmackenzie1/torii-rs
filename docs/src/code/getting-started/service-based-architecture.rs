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

    // All authentication methods are now available as services
    let _user = torii.password().register("user@example.com", "password").await?;
    let (_user, _session) = torii.password().authenticate("user@example.com", "password", None, None).await?;

    Ok(())
}